import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from motor.motor_asyncio import AsyncIOMotorDatabase
from prometheus_client import Counter
from pydantic import ValidationError

from app.core import security
from app.core.config import settings
from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP
from app.core.permissions import Permissions, has_permission
from app.db.mongodb import get_database
from app.models.project import Project
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories import (
    ProjectRepository,
    SystemSettingsRepository,
    TeamRepository,
    UserRepository,
)
from app.repositories.api_keys import ApiKeyRepository
from app.schemas.token import TokenPayload
from app.services.gitlab import GitLabService

if TYPE_CHECKING:
    from app.services.github import GitHubService

logger = logging.getLogger(__name__)

_MSG_INVALID_API_KEY = "Invalid API Key"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")
optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token", auto_error=False)

auth_token_validations_total: Counter | None = None

try:
    from app.core.metrics import auth_token_validations_total
except ImportError:
    pass


async def get_system_settings(
    db: AsyncIOMotorDatabase = Depends(get_database),
    auto_init: bool = False,
) -> SystemSettings:
    """Get system settings; create defaults in DB when auto_init is True."""
    repo = SystemSettingsRepository(db)
    return await repo.get(auto_init=auto_init)


def _decode_user_token(token: str, credentials_exception: HTTPException) -> tuple[dict, TokenPayload]:
    """Decode JWT and return (payload, token_data). Raises credentials_exception on failure."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        permissions: list[str] = payload.get("permissions", [])
        if username is None:
            raise credentials_exception
        token_data = TokenPayload(sub=username, permissions=permissions)
    except (JWTError, ValidationError) as exc:
        if auth_token_validations_total:
            auth_token_validations_total.labels(result="invalid").inc()
        raise credentials_exception from exc
    return payload, token_data


async def _ensure_token_not_blacklisted(jti: str | None, db: AsyncIOMotorDatabase) -> None:
    if not jti:
        return
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


def _check_logout_invalidation(user: dict, payload: dict, credentials_exception: HTTPException) -> None:
    """Raise credentials_exception if the token was issued before the user's last logout."""
    last_logout_at = user.get("last_logout_at")
    if not last_logout_at:
        return
    iat = payload.get("iat")
    if not iat:
        return
    if iat < last_logout_at.timestamp():
        if auth_token_validations_total:
            auth_token_validations_total.labels(result="revoked").inc()
        raise credentials_exception


async def get_current_user(
    db: AsyncIOMotorDatabase = Depends(get_database),
    token: str = Depends(oauth2_scheme),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload, token_data = _decode_user_token(token, credentials_exception)

    await _ensure_token_not_blacklisted(payload.get("jti"), db)

    user_repo = UserRepository(db)
    if not token_data.sub:
        raise credentials_exception
    user = await user_repo.get_raw_by_username(token_data.sub)
    if user is None:
        if auth_token_validations_total:
            auth_token_validations_total.labels(result="user_not_found").inc()
        raise credentials_exception

    _check_logout_invalidation(user, payload, credentials_exception)

    if auth_token_validations_total:
        auth_token_validations_total.labels(result="valid").inc()

    user_obj = User(**user)

    # A single-scope setup_2fa token grants only that permission.
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
    """Permission dependency requiring ANY of the given permissions (no wildcard support)."""

    def __init__(self, required_permissions: str | list[str]):
        self.required_permissions = (
            required_permissions if isinstance(required_permissions, list) else [required_permissions]
        )

    def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        from app.core.permissions import has_permission

        if has_permission(current_user.permissions, self.required_permissions):
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not enough permissions. Required one of: {', '.join(self.required_permissions)}",
        )


async def _resolve_initial_member_id(
    user_repo: UserRepository, email: str | None = None, username: str | None = None
) -> str | None:
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


async def _should_overwrite_team_id_from_sync(
    project_team_id: str | None,
    team_repo: TeamRepository,
    team_source: str | None = None,
) -> bool:
    """Whether VCS sync may overwrite project.team_id.

    A manual team_source is never reverted by sync. For legacy projects
    (team_source unknown), overwrite only when there is no team, the team is
    missing, or the current team itself came from a sync.
    """
    if team_source == "manual":
        return False
    if not project_team_id:
        return True
    current_team = await team_repo.get_raw_by_id(project_team_id)
    if not current_team:
        return True
    return bool(current_team.get("gitlab_group_id") or current_team.get("github_team_id"))


async def _gitlab_team_sync_update(
    project: Project,
    gitlab_project_id: int,
    gitlab_project_path: str,
    gitlab_service: "GitLabService",
    db: AsyncIOMotorDatabase,
) -> dict:
    """Return the team_id update GitLab sync should merge, or an empty dict to skip."""
    gitlab_project_data = await gitlab_service.get_project_details(gitlab_project_id)
    team_id = await gitlab_service.sync_team_from_gitlab(
        db,
        gitlab_project_id,
        gitlab_project_path,
        gitlab_project_data=gitlab_project_data,
    )
    if not team_id or project.team_id == team_id:
        return {}
    team_repo = TeamRepository(db)
    if await _should_overwrite_team_id_from_sync(project.team_id, team_repo, project.team_source):
        # Stamp gitlab provenance so a later manual reassignment is not reverted on sync.
        return {"team_id": team_id, "team_source": "gitlab"}
    logger.info(
        f"Keeping manual team assignment for project {project.id} ({gitlab_project_path}); "
        f"GitLab sync would have set team_id={team_id}."
    )
    return {}


async def _github_team_sync_update(
    project: Project,
    github_org: str,
    repository_path: str,
    github_service: "GitHubService",
    db: AsyncIOMotorDatabase,
) -> dict:
    """Return the team update GitHub sync should merge, or an empty dict to skip."""
    result = await github_service.sync_team_from_github(db, github_org, repository_path)
    updates: dict = {}
    # None means the candidate list was never determined; keep the last known count.
    if result.candidate_count is not None and result.candidate_count != project.github_team_candidates:
        updates["github_team_candidates"] = result.candidate_count
    if not result.team_id or project.team_id == result.team_id:
        return updates
    team_repo = TeamRepository(db)
    if await _should_overwrite_team_id_from_sync(project.team_id, team_repo, project.team_source):
        # Stamp github provenance so a later manual reassignment is not reverted on sync.
        updates["team_id"] = result.team_id
        updates["team_source"] = "github"
        return updates
    logger.info(
        f"Keeping manual team assignment for project {project.id} ({repository_path}); "
        f"GitHub sync would have set team_id={result.team_id}."
    )
    return updates


async def _sync_project_name(
    project: Project,
    new_path: str,
    project_repo: ProjectRepository,
    path_field: str = "gitlab_project_path",
    extra_updates: dict | None = None,
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

    project_data = await project_repo.get_raw_by_gitlab_composite_key(instance_id, gitlab_project_id)

    if project_data:
        project = Project(**project_data)
        extra_updates: dict = {}

        if gitlab_instance.sync_teams:
            extra_updates.update(
                await _gitlab_team_sync_update(project, gitlab_project_id, gitlab_project_path, gitlab_service, db)
            )

        return await _sync_project_name(
            project,
            gitlab_project_path,
            project_repo,
            path_field="gitlab_project_path",
            extra_updates=extra_updates,
        )

    if not gitlab_instance.auto_create_projects:
        raise HTTPException(
            status_code=404,
            detail=f"Project not found on instance '{gitlab_instance.name}' and auto-creation is disabled",
        )

    initial_member_id = await _resolve_initial_member_id(user_repo, email=payload.user_email)
    members = [ProjectMember(user_id=initial_member_id, role="admin")] if initial_member_id else []

    team_id = None
    team_source = None
    if gitlab_instance.sync_teams:
        gitlab_project_data = await gitlab_service.get_project_details(gitlab_project_id)
        team_id = await gitlab_service.sync_team_from_gitlab(
            db,
            gitlab_project_id,
            gitlab_project_path,
            gitlab_project_data=gitlab_project_data,
        )
        if team_id:
            team_source = "gitlab"

    new_project = Project(
        name=gitlab_project_path,
        members=members,
        gitlab_instance_id=instance_id,
        gitlab_project_id=gitlab_project_id,
        gitlab_project_path=gitlab_project_path,
        default_branch=None,
        active_analyzers=default_analyzers,
        team_id=team_id,
        team_source=team_source,
    )

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

    project_data = await project_repo.get_raw_by_github_composite_key(instance_id, repo_id)
    if project_data:
        project = Project(**project_data)
        extra_updates: dict = {}

        if github_instance.sync_teams:
            extra_updates.update(
                await _github_team_sync_update(project, gh_payload.repository_owner, repo_path, github_service, db)
            )

        return await _sync_project_name(
            project,
            repo_path,
            project_repo,
            path_field="github_repository_path",
            extra_updates=extra_updates,
        )

    if not github_instance.auto_create_projects:
        raise HTTPException(
            status_code=404,
            detail=f"Project not found on GitHub instance '{github_instance.name}' and auto-creation is disabled",
        )

    initial_member_id = await _resolve_initial_member_id(user_repo, username=gh_payload.actor)
    members = [ProjectMember(user_id=initial_member_id, role="admin")] if initial_member_id else []

    github_team_candidates = None
    team_id = None
    team_source = None
    if github_instance.sync_teams:
        sync_result = await github_service.sync_team_from_github(db, gh_payload.repository_owner, repo_path)
        github_team_candidates = sync_result.candidate_count
        if sync_result.team_id:
            team_id = sync_result.team_id
            team_source = "github"

    new_project = Project(
        name=repo_path,
        members=members,
        github_instance_id=instance_id,
        github_repository_id=repo_id,
        github_repository_path=repo_path,
        default_branch=None,
        active_analyzers=default_analyzers,
        github_team_candidates=github_team_candidates,
        team_id=team_id,
        team_source=team_source,
    )

    project, created = await project_repo.find_or_create_by_github_key(instance_id, repo_id, new_project)
    if created:
        logger.info(f"Auto-created project '{repo_path}' from GitHub instance '{github_instance.name}'")
    return project


async def _authenticate_via_api_key(x_api_key: str, project_repo: ProjectRepository) -> "Project":
    from app.models.project import Project

    if "." not in x_api_key:
        raise HTTPException(status_code=403, detail="Invalid API Key format")
    project_id, secret = x_api_key.split(".", 1)
    project_data = await project_repo.get_raw_by_id(project_id)
    if not project_data or not project_data.get("api_key_hash"):
        raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)
    if not security.verify_password(secret, project_data["api_key_hash"]):
        raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)
    return Project(**project_data)


def _extract_oidc_issuer(oidc_token: str) -> str:
    if len(oidc_token.split(".")) != 3:
        raise HTTPException(status_code=403, detail="Invalid Token format. Expected a JWT (OIDC) token.")

    from jose import jwt as jose_jwt

    try:
        unverified_payload = jose_jwt.get_unverified_claims(oidc_token)
        issuer = unverified_payload.get("iss")
    except Exception as e:
        logger.exception("Failed to decode OIDC token: %s", e)
        raise HTTPException(status_code=403, detail="Invalid OIDC token format")

    if not issuer:
        raise HTTPException(status_code=403, detail="OIDC token missing issuer (iss) claim")
    return str(issuer)


async def _authenticate_via_oidc(
    oidc_token: str,
    db: AsyncIOMotorDatabase,
    project_repo: ProjectRepository,
    user_repo: UserRepository,
    default_active_analyzers: list[str],
) -> "Project":
    from app.repositories.github_instances import GitHubInstanceRepository
    from app.repositories.gitlab_instances import GitLabInstanceRepository

    issuer = _extract_oidc_issuer(oidc_token)

    gitlab_instance = await GitLabInstanceRepository(db).get_by_url(issuer)
    if gitlab_instance:
        return await _handle_gitlab_oidc(
            oidc_token,
            gitlab_instance,
            db,
            project_repo,
            user_repo,
            default_active_analyzers,
        )

    github_instance = await GitHubInstanceRepository(db).get_by_url(issuer)
    if github_instance:
        return await _handle_github_oidc(
            oidc_token,
            github_instance,
            db,
            project_repo,
            user_repo,
            default_active_analyzers,
        )

    raise HTTPException(
        status_code=403,
        detail=f"No CI/CD instance configured for OIDC issuer: {issuer}. "
        "Configure a GitLab or GitHub instance with this issuer URL.",
    )


async def get_project_for_ingest(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    oidc_token: str | None = Header(None, alias="Job-Token"),
    db: AsyncIOMotorDatabase = Depends(get_database),
    settings: SystemSettings = Depends(get_system_settings),
) -> Project:
    project_repo = ProjectRepository(db)
    user_repo = UserRepository(db)

    if x_api_key:
        return await _authenticate_via_api_key(x_api_key, project_repo)

    if oidc_token:
        return await _authenticate_via_oidc(oidc_token, db, project_repo, user_repo, settings.default_active_analyzers)

    raise HTTPException(status_code=401, detail="Missing authentication credentials")


async def authorize_callgraph_write(
    project_id: str,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    oidc_token: str | None = Header(None, alias="Job-Token"),
    token: str | None = Depends(optional_oauth2_scheme),
    db: AsyncIOMotorDatabase = Depends(get_database),
    settings_: SystemSettings = Depends(get_system_settings),
) -> str:
    """Authorize a callgraph write for CI credentials or a logged-in user; returns the project id."""
    from app.api.v1.helpers.callgraph import check_callgraph_access

    if x_api_key or oidc_token:
        project = await get_project_for_ingest(x_api_key=x_api_key, oidc_token=oidc_token, db=db, settings=settings_)
        if str(project.id) != project_id:
            raise HTTPException(status_code=403, detail="CI credentials do not match the target project")
        return project_id

    if token:
        user = await get_current_user(db=db, token=token)
        await check_callgraph_access(project_id, await get_current_active_user(user), db, require_write=True)
        return project_id

    raise HTTPException(status_code=401, detail="Missing authentication credentials")


async def authorize_release_write(
    project_id: str,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    oidc_token: str | None = Header(None, alias="Job-Token"),
    token: str | None = Depends(optional_oauth2_scheme),
    db: AsyncIOMotorDatabase = Depends(get_database),
    settings_: SystemSettings = Depends(get_system_settings),
) -> str:
    """Authorize a release mark for CI credentials or a logged-in editor; returns the project id.

    The deploy stage runs long after the build, so the CD job marks with the same credentials it
    ingested with, while a human correcting a mistake has only a session.
    """
    from app.api.v1.helpers.projects import check_project_access
    from app.core.constants import PROJECT_ROLE_EDITOR

    if x_api_key or oidc_token:
        project = await get_project_for_ingest(x_api_key=x_api_key, oidc_token=oidc_token, db=db, settings=settings_)
        if str(project.id) != project_id:
            raise HTTPException(status_code=403, detail="CI credentials do not match the target project")
        return project_id

    if token:
        user = await get_current_user(db=db, token=token)
        await check_project_access(
            project_id, await get_current_active_user(user), db, required_role=PROJECT_ROLE_EDITOR
        )
        return project_id

    raise HTTPException(status_code=401, detail="Missing authentication credentials")


async def get_adhoc_api_key(
    authorization: str = Header(default=""),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict[str, Any]:
    """Resolve an ad-hoc analysis Bearer token to its key document.

    No usage timestamp is stamped: the ad-hoc endpoint persists nothing, auth included.
    """
    from app.core.permissions import Permissions, has_permission
    from app.repositories.adhoc_api_keys import AdhocApiKeyRepository

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="analyze"'},
        )
    token = authorization.split(" ", 1)[1].strip()
    key_doc = await AdhocApiKeyRepository(db).get_by_plaintext(token)
    if not key_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, revoked, or expired ad-hoc API key",
        )

    user = await UserRepository(db).get_by_id(key_doc["user_id"])
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token owner is no longer active")
    if not has_permission(user.permissions, Permissions.ANALYZE_ADHOC):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token owner no longer has ad-hoc analysis access",
        )
    return key_doc


# A key names the doors it may open; the owner's permission decides whether a named door is still
# theirs to walk through. Both are checked on every request, so the pairing is stated once here.
_SURFACE_PERMISSIONS: dict[str, str] = {
    API_KEY_SURFACE_MCP: Permissions.MCP_ACCESS,
    API_KEY_SURFACE_ADHOC: Permissions.ANALYZE_ADHOC,
}


def require_api_key(surface: str, *, touch: bool = False) -> Callable[..., Awaitable[tuple[User, dict[str, Any]]]]:
    """Build the dependency guarding one key-authenticated surface: it resolves the Bearer token to
    its (owner, key document) pair and admits the caller only when the key names the surface and the
    owner still holds that surface's permission; ``touch`` stamps the key's last use, which a
    surface promising to persist nothing leaves off."""
    permission = _SURFACE_PERMISSIONS[surface]

    async def dependency(
        authorization: str = Header(default=""),
        db: AsyncIOMotorDatabase = Depends(get_database),
    ) -> tuple[User, dict[str, Any]]:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer token",
                headers={"WWW-Authenticate": f'Bearer realm="{surface}"'},
            )
        token = authorization.split(" ", 1)[1].strip()
        key_repo = ApiKeyRepository(db)
        key_doc = await key_repo.get_by_plaintext(token)
        if not key_doc:
            # Unknown, revoked and expired share one message: telling them apart would confirm to
            # the holder of a rejected token that it once existed.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, revoked, or expired API key",
            )

        user = await UserRepository(db).get_by_id(key_doc["user_id"])
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token owner is no longer active")
        if not has_permission(user.permissions, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token owner no longer has {surface} access",
            )
        # A key document carrying no surface list names no surface, so the gate stays closed.
        if surface not in key_doc.get("surfaces", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not grant the {surface} surface",
            )

        if touch:
            await key_repo.touch_last_used(key_doc["_id"])
        return user, key_doc

    return dependency


DatabaseDep = Annotated[AsyncIOMotorDatabase[Any], Depends(get_database)]
CurrentUserDep = Annotated[User, Depends(get_current_active_user)]
CallgraphWriteDep = Annotated[str, Depends(authorize_callgraph_write)]
ReleaseWriteDep = Annotated[str, Depends(authorize_release_write)]
AdhocKeyDep = Annotated[dict[str, Any], Depends(get_adhoc_api_key)]
