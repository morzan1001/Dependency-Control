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
from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP, MAX_PROJECT_TEAMS
from app.core.permissions import Permissions, has_permission
from app.db.mongodb import get_database
from app.models.project import Project
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories import (
    ProjectRepository,
    SystemSettingsRepository,
    UserRepository,
)
from app.repositories.api_keys import ApiKeyRepository
from app.repositories.projects import literal_set_stage, ownership_fields, replace_team_subset_pipeline
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


def _resolved_owners(source: str, resolved: list[str] | None, repository_path: str) -> list[str] | None:
    """The owners this provider resolved, or None when its answer must not be acted on.

    ``None`` from the provider is "it could not be asked", which must never read as "no team holds
    this repository": the first leaves the owners it set alone, the second drops every one of them.
    A resolution past the cap is refused rather than truncated — which of them to drop is not a
    question a sync can answer.
    """
    if resolved is None:
        return None
    owners = sorted(set(resolved))
    if len(owners) > MAX_PROJECT_TEAMS:
        logger.warning(
            "%s sync resolved %d owning teams for %s, past the cap of %d; leaving its owners untouched.",
            source,
            len(owners),
            repository_path,
            MAX_PROJECT_TEAMS,
        )
        return None
    return owners


def _team_subset_stages(project: Project, source: str, resolved: list[str] | None, repository_path: str) -> list[dict]:
    """The ownership stages this provider contributes, empty when there is nothing for it to write."""
    owners = _resolved_owners(source, resolved, repository_path)
    if owners is None:
        return []
    owned_here = {team_id for team_id, entry in project.team_sources.items() if entry == source}
    # Every CI job of every pipeline arrives here, so an unchanged owner set writes nothing. The
    # second half catches a document whose provenance names an owner the list never gained.
    if owned_here == set(owners) and owned_here <= set(project.team_ids):
        return []
    return replace_team_subset_pipeline(source, owners)


async def _gitlab_team_sync_stages(
    project: Project,
    gitlab_project_id: int,
    gitlab_project_path: str,
    gitlab_service: "GitLabService",
    db: AsyncIOMotorDatabase,
) -> list[dict]:
    """The ownership stages GitLab sync contributes to this ingest's update."""
    gitlab_project_data = await gitlab_service.get_project_details(gitlab_project_id)
    resolved = await gitlab_service.sync_team_from_gitlab(
        db,
        gitlab_project_id,
        gitlab_project_path,
        gitlab_project_data=gitlab_project_data,
    )
    return _team_subset_stages(project, "gitlab", resolved.team_ids, gitlab_project_path)


async def _github_team_sync_stages(
    project: Project,
    github_org: str,
    repository_path: str,
    github_service: "GitHubService",
    db: AsyncIOMotorDatabase,
) -> list[dict]:
    """The ownership stages GitHub sync contributes to this ingest's update."""
    result = await github_service.sync_team_from_github(db, github_org, repository_path)
    return _team_subset_stages(project, "github", result.team_ids, repository_path)


async def _sync_project_name(
    project: Project,
    new_path: str,
    project_repo: ProjectRepository,
    path_field: str = "gitlab_project_path",
    ownership_stages: list[dict] | None = None,
) -> Project:
    """Apply the rename and the resolved ownership as one update.

    The ownership half is a pipeline, which cannot be merged into the ``$set`` document the rename
    is: both become stages of one pipeline instead, so an ingest still writes the project once.
    """
    stages: list[dict] = []
    renamed: dict = {}
    current_path = getattr(project, path_field, None)
    if current_path and current_path != new_path:
        renamed[path_field] = new_path
        if project.name == current_path:
            renamed["name"] = new_path
    if renamed:
        stages.append(literal_set_stage(renamed))
    stages.extend(ownership_stages or [])

    if not stages:
        return project
    await project_repo.update_raw(project.id, stages)
    # The owners are computed server-side, so the caller is handed what was stored, not a guess.
    return await project_repo.get_by_id_strong(project.id) or project


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
        ownership_stages: list[dict] = []

        if gitlab_instance.sync_teams:
            ownership_stages = await _gitlab_team_sync_stages(
                project, gitlab_project_id, gitlab_project_path, gitlab_service, db
            )

        return await _sync_project_name(
            project,
            gitlab_project_path,
            project_repo,
            path_field="gitlab_project_path",
            ownership_stages=ownership_stages,
        )

    if not gitlab_instance.auto_create_projects:
        raise HTTPException(
            status_code=404,
            detail=f"Project not found on instance '{gitlab_instance.name}' and auto-creation is disabled",
        )

    initial_member_id = await _resolve_initial_member_id(user_repo, email=payload.user_email)
    members = [ProjectMember(user_id=initial_member_id, role="admin")] if initial_member_id else []

    owners: list[str] = []
    if gitlab_instance.sync_teams:
        gitlab_project_data = await gitlab_service.get_project_details(gitlab_project_id)
        resolved = await gitlab_service.sync_team_from_gitlab(
            db,
            gitlab_project_id,
            gitlab_project_path,
            gitlab_project_data=gitlab_project_data,
        )
        owners = _resolved_owners("gitlab", resolved.team_ids, gitlab_project_path) or []

    new_project = Project(
        name=gitlab_project_path,
        members=members,
        gitlab_instance_id=instance_id,
        gitlab_project_id=gitlab_project_id,
        gitlab_project_path=gitlab_project_path,
        default_branch=None,
        active_analyzers=default_analyzers,
        **ownership_fields(owners, "gitlab"),
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
        ownership_stages: list[dict] = []

        if github_instance.sync_teams:
            ownership_stages = await _github_team_sync_stages(
                project, gh_payload.repository_owner, repo_path, github_service, db
            )

        return await _sync_project_name(
            project,
            repo_path,
            project_repo,
            path_field="github_repository_path",
            ownership_stages=ownership_stages,
        )

    if not github_instance.auto_create_projects:
        raise HTTPException(
            status_code=404,
            detail=f"Project not found on GitHub instance '{github_instance.name}' and auto-creation is disabled",
        )

    initial_member_id = await _resolve_initial_member_id(user_repo, username=gh_payload.actor)
    members = [ProjectMember(user_id=initial_member_id, role="admin")] if initial_member_id else []

    owners: list[str] = []
    if github_instance.sync_teams:
        sync_result = await github_service.sync_team_from_github(db, gh_payload.repository_owner, repo_path)
        owners = _resolved_owners("github", sync_result.team_ids, repo_path) or []

    new_project = Project(
        name=repo_path,
        members=members,
        github_instance_id=instance_id,
        github_repository_id=repo_id,
        github_repository_path=repo_path,
        default_branch=None,
        active_analyzers=default_analyzers,
        **ownership_fields(owners, "github"),
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


# A key names the doors it may open; the owner's permission decides whether a named door is still
# theirs to walk through. Both are checked on every request, so the pairing is stated once here.
SURFACE_PERMISSIONS: dict[str, str] = {
    API_KEY_SURFACE_MCP: Permissions.MCP_ACCESS,
    API_KEY_SURFACE_ADHOC: Permissions.ANALYZE_ADHOC,
}


# Unknown, revoked and expired share one message: telling them apart would confirm to the holder
# of a rejected token that it once existed.
_MSG_UNRESOLVED_KEY = "Invalid, revoked, or expired API key"


def _bearer_token(authorization: str, surface: str) -> str:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": f'Bearer realm="{surface}"'},
        )
    return authorization.split(" ", 1)[1].strip()


async def _key_owner(db: AsyncIOMotorDatabase, key_doc: dict[str, Any]) -> User:
    # A document missing user_id resolves to no user, which the next line turns into a 401.
    user = await UserRepository(db).get_by_id(key_doc.get("user_id", ""))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token owner is no longer active")
    return user


def _require_permission(user: User, surface: str, permission: str) -> None:
    if not has_permission(user.permissions, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token owner no longer has {surface} access",
        )


async def _admit_unified_key(
    db: AsyncIOMotorDatabase,
    token: str,
    surface: str,
    permission: str,
    touch: bool,
) -> tuple[User, dict[str, Any]] | None:
    """The (owner, key document) pair behind a unified token, or None when no unified key answers."""
    key_repo = ApiKeyRepository(db)
    key_doc = await key_repo.get_by_plaintext(token)
    if not key_doc:
        return None

    user = await _key_owner(db, key_doc)
    # A write from outside ApiKeyRepository.create can leave surfaces absent or a non-list, and
    # a bare membership test against those admits substrings and dict keys.
    surfaces = key_doc.get("surfaces")
    if not isinstance(surfaces, list) or surface not in surfaces:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key does not grant the {surface} surface",
        )
    # Answered second: a key that never named the surface must not learn what its owner holds.
    _require_permission(user, surface, permission)

    if touch:
        await key_repo.touch_last_used(key_doc.get("_id", ""))
    return user, key_doc


def require_api_key(surface: str, *, touch: bool = False) -> Callable[..., Awaitable[tuple[User, dict[str, Any]]]]:
    """Build the dependency guarding one key-authenticated surface: it resolves the Bearer token to
    its (owner, key document) pair and admits the caller only when the key names the surface and the
    owner still holds that surface's permission; ``touch`` stamps the key's last use, which a
    surface promising to persist nothing leaves off."""
    permission = SURFACE_PERMISSIONS[surface]

    async def dependency(
        authorization: str = Header(default=""),
        db: AsyncIOMotorDatabase = Depends(get_database),
    ) -> tuple[User, dict[str, Any]]:
        token = _bearer_token(authorization, surface)
        admitted = await _admit_unified_key(db, token, surface, permission, touch)
        if admitted is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_MSG_UNRESOLVED_KEY)
        return admitted

    return dependency


DatabaseDep = Annotated[AsyncIOMotorDatabase[Any], Depends(get_database)]
CurrentUserDep = Annotated[User, Depends(get_current_active_user)]
CallgraphWriteDep = Annotated[str, Depends(authorize_callgraph_write)]
ReleaseWriteDep = Annotated[str, Depends(authorize_release_write)]
AdhocKeyDep = Annotated[
    tuple[User, dict[str, Any]],
    Depends(require_api_key(API_KEY_SURFACE_ADHOC)),
]
