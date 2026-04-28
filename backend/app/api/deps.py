import logging
from typing import Annotated, Any, List, Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from motor.motor_asyncio import AsyncIOMotorDatabase
from prometheus_client import Counter
from pydantic import ValidationError

from app.core import security
from app.core.config import settings
from app.db.mongodb import get_database
from app.models.project import Project
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories import (
    ProjectRepository,
    SystemSettingsRepository,
    UserRepository,
)
from app.schemas.token import TokenPayload
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)

_MSG_INVALID_API_KEY = "Invalid API Key"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")

# Import metrics for token validation tracking
auth_token_validations_total: Optional[Counter] = None

try:
    from app.core.metrics import auth_token_validations_total
except ImportError:
    pass


async def get_system_settings(
    db: AsyncIOMotorDatabase = Depends(get_database),
    auto_init: bool = False,
) -> SystemSettings:
    """
    Get system settings from database.

    Args:
        db: Database connection
        auto_init: If True, creates default settings in DB if not found
    """
    repo = SystemSettingsRepository(db)
    return await repo.get(auto_init=auto_init)


async def get_current_user(
    db: AsyncIOMotorDatabase = Depends(get_database),
    token: str = Depends(oauth2_scheme),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        permissions: list[str] = payload.get("permissions", [])
        jti = payload.get("jti")  # JWT ID for blacklist check

        if username is None:
            raise credentials_exception
        token_data = TokenPayload(sub=username, permissions=permissions)
    except (JWTError, ValidationError) as exc:
        if auth_token_validations_total:
            auth_token_validations_total.labels(result="invalid").inc()
        raise credentials_exception from exc

    # Check if token is blacklisted (logout invalidation)
    if jti:
        from app.repositories import TokenBlacklistRepository

        blacklist_repo = TokenBlacklistRepository(db)
        if await blacklist_repo.is_blacklisted(jti):
            if auth_token_validations_total:
                auth_token_validations_total.labels(result="blacklisted").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user_repo = UserRepository(db)
    if not token_data.sub:
        raise credentials_exception
    user = await user_repo.get_raw_by_username(token_data.sub)
    if user is None:
        if auth_token_validations_total:
            auth_token_validations_total.labels(result="user_not_found").inc()
        raise credentials_exception

    # Check if token was issued before last logout
    if "last_logout_at" in user and user["last_logout_at"]:
        iat = payload.get("iat")
        if iat:
            # iat is unix timestamp, last_logout_at is datetime
            last_logout_ts = user["last_logout_at"].timestamp()
            if iat < last_logout_ts:
                if auth_token_validations_total:
                    auth_token_validations_total.labels(result="revoked").inc()
                raise credentials_exception

    if auth_token_validations_total:
        auth_token_validations_total.labels(result="valid").inc()

    user_obj = User(**user)

    # If token has restricted permissions (e.g. only setup_2fa), override user permissions
    if token_data.permissions and "auth:setup_2fa" in token_data.permissions and len(token_data.permissions) == 1:
        user_obj.permissions = token_data.permissions

    return user_obj


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


class PermissionChecker:
    """
    FastAPI dependency for permission-based access control.

    Checks if the current user has any of the required permissions.
    No wildcard ("*") support - admins must have all permissions explicitly.
    """

    def __init__(self, required_permissions: str | List[str]):
        self.required_permissions = (
            required_permissions if isinstance(required_permissions, list) else [required_permissions]
        )

    def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        from app.core.permissions import has_permission

        # Check if user has ANY of the required permissions
        if has_permission(current_user.permissions, self.required_permissions):
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not enough permissions. Required one of: {', '.join(self.required_permissions)}",
        )


async def get_project_by_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> Project:
    if "." not in x_api_key:
        raise HTTPException(
            status_code=403,
            detail="Invalid API Key format. Expected 'project_id.secret'",
        )

    project_id, secret = x_api_key.split(".", 1)

    project_repo = ProjectRepository(db)
    project_data = await project_repo.get_raw_by_id(project_id)
    if not project_data:
        raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)

    stored_hash = project_data.get("api_key_hash")
    if not stored_hash:
        raise HTTPException(status_code=403, detail="Project has no API key set")

    if not security.verify_password(secret, stored_hash):
        raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)

    from app.models.project import Project

    return Project(**project_data)


async def _resolve_initial_member_id(
    user_repo: UserRepository, email: Optional[str] = None, username: Optional[str] = None
) -> Optional[str]:
    """Resolve a user ID to add as initial project admin member. Returns None if no match."""
    if email:
        user = await user_repo.get_raw_by_email(email)
        if user:
            return str(user["_id"])
    if username:
        user = await user_repo.get_raw_by_username(username)
        if user:
            return str(user["_id"])
    return None


async def _sync_project_name(
    project: Project,
    new_path: str,
    project_repo: ProjectRepository,
    path_field: str = "gitlab_project_path",
    extra_updates: Optional[dict] = None,
) -> Project:
    """Sync project path/name if the VCS project was renamed."""
    updates: dict = extra_updates or {}
    current_path = getattr(project, path_field, None)
    if current_path and current_path != new_path:
        updates[path_field] = new_path
        if project.name == current_path:
            updates["name"] = new_path

    if updates:
        await project_repo.update(project.id, updates)
        for key, value in updates.items():
            setattr(project, key, value)
    return project


async def _handle_gitlab_oidc(
    oidc_token: str,
    gitlab_instance: Any,
    db: AsyncIOMotorDatabase,
    project_repo: ProjectRepository,
    user_repo: UserRepository,
    default_analyzers: list,
) -> Project:
    """Handle GitLab OIDC authentication and project resolution."""
    from app.models.project import Project, ProjectMember

    if not gitlab_instance.is_active:
        raise HTTPException(status_code=403, detail=f"GitLab instance '{gitlab_instance.name}' is not active")

    gitlab_service = GitLabService(gitlab_instance)
    payload = await gitlab_service.validate_oidc_token(oidc_token)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid GitLab OIDC Token")

    gitlab_project_id = int(payload.project_id)
    gitlab_project_path = payload.project_path
    instance_id = str(gitlab_instance.id)

    # Find existing project
    project_data = await project_repo.get_raw_by_gitlab_composite_key(instance_id, gitlab_project_id)

    if project_data:
        project = Project(**project_data)
        extra_updates: dict = {}

        if gitlab_instance.sync_teams:
            gitlab_project_data = await gitlab_service.get_project_details(gitlab_project_id)
            team_id = await gitlab_service.sync_team_from_gitlab(
                db,
                gitlab_project_id,
                gitlab_project_path,
                gitlab_project_data=gitlab_project_data,
            )
            if team_id and project.team_id != team_id:
                extra_updates["team_id"] = team_id

        return await _sync_project_name(
            project,
            gitlab_project_path,
            project_repo,
            path_field="gitlab_project_path",
            extra_updates=extra_updates,
        )

    # Auto-create
    if not gitlab_instance.auto_create_projects:
        raise HTTPException(
            status_code=404,
            detail=f"Project not found on instance '{gitlab_instance.name}' and auto-creation is disabled",
        )

    initial_member_id = await _resolve_initial_member_id(user_repo, email=payload.user_email)
    members = [ProjectMember(user_id=initial_member_id, role="admin")] if initial_member_id else []
    new_project = Project(
        name=gitlab_project_path,
        members=members,
        gitlab_instance_id=instance_id,
        gitlab_project_id=gitlab_project_id,
        gitlab_project_path=gitlab_project_path,
        default_branch=None,
        active_analyzers=default_analyzers,
    )

    if gitlab_instance.sync_teams:
        gitlab_project_data = await gitlab_service.get_project_details(gitlab_project_id)
        team_id = await gitlab_service.sync_team_from_gitlab(
            db,
            gitlab_project_id,
            gitlab_project_path,
            gitlab_project_data=gitlab_project_data,
        )
        if team_id:
            new_project.team_id = team_id

    project, created = await project_repo.find_or_create_by_gitlab_key(instance_id, gitlab_project_id, new_project)
    if created:
        logger.info(f"Auto-created project '{gitlab_project_path}' from GitLab instance '{gitlab_instance.name}'")
    return project


async def _handle_github_oidc(
    oidc_token: str,
    github_instance: Any,
    db: AsyncIOMotorDatabase,
    project_repo: ProjectRepository,
    user_repo: UserRepository,
    default_analyzers: list,
) -> Project:
    """Handle GitHub OIDC authentication and project resolution."""
    from app.models.project import Project, ProjectMember
    from app.services.github import GitHubService

    if not github_instance.is_active:
        raise HTTPException(status_code=403, detail=f"GitHub instance '{github_instance.name}' is not active")

    github_service = GitHubService(github_instance)
    gh_payload = await github_service.validate_oidc_token(oidc_token)
    if not gh_payload:
        raise HTTPException(status_code=403, detail="Invalid GitHub Actions OIDC Token")

    instance_id = str(github_instance.id)
    repo_id = gh_payload.repository_id
    repo_path = gh_payload.repository

    # Find existing project
    project_data = await project_repo.get_raw_by_github_composite_key(instance_id, repo_id)
    if project_data:
        return await _sync_project_name(
            Project(**project_data),
            repo_path,
            project_repo,
            path_field="github_repository_path",
        )

    # Auto-create
    if not github_instance.auto_create_projects:
        raise HTTPException(
            status_code=404,
            detail=f"Project not found on GitHub instance '{github_instance.name}' and auto-creation is disabled",
        )

    initial_member_id = await _resolve_initial_member_id(user_repo, username=gh_payload.actor)
    members = [ProjectMember(user_id=initial_member_id, role="admin")] if initial_member_id else []
    new_project = Project(
        name=repo_path,
        members=members,
        github_instance_id=instance_id,
        github_repository_id=repo_id,
        github_repository_path=repo_path,
        default_branch=None,
        active_analyzers=default_analyzers,
    )

    project, created = await project_repo.find_or_create_by_github_key(instance_id, repo_id, new_project)
    if created:
        logger.info(f"Auto-created project '{repo_path}' from GitHub instance '{github_instance.name}'")
    return project


async def get_project_for_ingest(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    oidc_token: Optional[str] = Header(None, alias="Job-Token"),
    db: AsyncIOMotorDatabase = Depends(get_database),
    settings: SystemSettings = Depends(get_system_settings),
) -> Project:
    from app.models.project import Project

    project_repo = ProjectRepository(db)
    user_repo = UserRepository(db)

    # 1. Try API Key
    if x_api_key:
        if "." not in x_api_key:
            raise HTTPException(status_code=403, detail="Invalid API Key format")
        project_id, secret = x_api_key.split(".", 1)
        project_data = await project_repo.get_raw_by_id(project_id)
        if not project_data or not project_data.get("api_key_hash"):
            raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)
        if not security.verify_password(secret, project_data["api_key_hash"]):
            raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)
        return Project(**project_data)

    # 2. Try OIDC Token (GitLab or GitHub)
    if oidc_token:
        if len(oidc_token.split(".")) != 3:
            raise HTTPException(status_code=403, detail="Invalid Token format. Expected a JWT (OIDC) token.")

        from jose import jwt as jose_jwt
        from app.repositories.gitlab_instances import GitLabInstanceRepository
        from app.repositories.github_instances import GitHubInstanceRepository

        try:
            unverified_payload = jose_jwt.get_unverified_claims(oidc_token)
            issuer = unverified_payload.get("iss")
        except Exception as e:
            logger.error(f"Failed to decode OIDC token: {e}")
            raise HTTPException(status_code=403, detail="Invalid OIDC token format")

        if not issuer:
            raise HTTPException(status_code=403, detail="OIDC token missing issuer (iss) claim")

        # Try GitLab
        gitlab_instance = await GitLabInstanceRepository(db).get_by_url(issuer)
        if gitlab_instance:
            return await _handle_gitlab_oidc(
                oidc_token,
                gitlab_instance,
                db,
                project_repo,
                user_repo,
                settings.default_active_analyzers,
            )

        # Try GitHub
        github_instance = await GitHubInstanceRepository(db).get_by_url(issuer)
        if github_instance:
            return await _handle_github_oidc(
                oidc_token,
                github_instance,
                db,
                project_repo,
                user_repo,
                settings.default_active_analyzers,
            )

        raise HTTPException(
            status_code=403,
            detail=f"No CI/CD instance configured for OIDC issuer: {issuer}. "
            "Configure a GitLab or GitHub instance with this issuer URL.",
        )

    raise HTTPException(status_code=401, detail="Missing authentication credentials")


# Annotated type aliases for FastAPI dependency injection
DatabaseDep = Annotated[AsyncIOMotorDatabase[Any], Depends(get_database)]
CurrentUserDep = Annotated[User, Depends(get_current_active_user)]
