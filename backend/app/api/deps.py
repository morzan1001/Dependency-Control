import asyncio
import hmac
import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Annotated, Any, ClassVar, NamedTuple

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import security
from app.core.cache import cache_service
from app.core.config import settings
from app.core.constants import (
    API_KEY_LAST_USED_RESOLUTION_SECONDS,
    API_KEY_SURFACE_ADHOC,
    API_KEY_SURFACE_MCP,
    GITLAB_TEAM_SYNC_WINDOW_SECONDS,
    MAX_PROJECT_TEAMS,
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
)
from app.core.log_utils import sanitize_for_log
from app.core.metrics import auth_token_validations_total
from app.core.permissions import Permissions, has_permission, is_setup_2fa_scope
from app.db.mongodb import get_database
from app.models.project import Project, ProjectMember
from app.models.system import SystemSettings
from app.models.team import TeamSyncResult
from app.models.user import User
from app.repositories.api_keys import ApiKeyRepository, hash_token
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.projects import (
    ProjectRepository,
    owners_replaced_by,
    ownership_fields,
    replace_team_subset_pipeline,
)
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.token_blacklist import TokenBlacklistRepository
from app.repositories.users import UserRepository
from app.schemas.token import TokenPayload
from app.services.github import GitHubService
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)

_MSG_INVALID_API_KEY = "Invalid API Key"
# Live project keys issued under argon2 keep that hash until their first verification rewrites it.
_ARGON2_PREFIX = "$argon2"
_MSG_CI_PROJECT_MISMATCH = "CI credentials do not match the target project"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")
optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token", auto_error=False)


async def get_system_settings(db: AsyncIOMotorDatabase = Depends(get_database)) -> SystemSettings:
    return await SystemSettingsRepository(db).get()


class TokenRejected(Exception):
    """``result`` is the auth_token_validations_total label a bearer rejection is counted under."""

    def __init__(self, result: str) -> None:
        super().__init__(result)
        self.result = result


async def decode_token(token: str, expected_type: str, db: AsyncIOMotorDatabase) -> tuple[TokenPayload, dict | None]:
    claims = security.decode_session_token(token, expected_type)
    if claims is None:
        raise TokenRejected("invalid")
    # last_logout_at revokes access tokens; the blacklist is what spends a rotated refresh token.
    if expected_type == "refresh" and await TokenBlacklistRepository(db).is_blacklisted(claims.jti):
        raise TokenRejected("blacklisted")

    user = await UserRepository(db).get_raw_by_id(claims.sub)
    last_logout_at = user.get("last_logout_at") if user else None
    if last_logout_at and claims.iat < last_logout_at.timestamp():
        raise TokenRejected("revoked")
    return claims, user


def _count_validation(result: str) -> None:
    auth_token_validations_total.labels(result=result).inc()


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
        token_data, user = await decode_token(token, "access", db)
    except TokenRejected as exc:
        _count_validation(exc.result)
        raise credentials_exception from exc
    if user is None:
        _count_validation("user_not_found")
        raise credentials_exception

    _count_validation("valid")

    user_obj = User(**user)
    if is_setup_2fa_scope(token_data.permissions):
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
        if has_permission(current_user.permissions, self.required_permissions):
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not enough permissions. Required one of: {', '.join(self.required_permissions)}",
        )


def _within_cap(source: str, would_own: set[str], repository_path: str) -> bool:
    """Whether the project's whole owner set fits the cap; refused, not truncated, as no sync can pick whom to drop."""
    if len(would_own) <= MAX_PROJECT_TEAMS:
        return True
    logger.warning(
        "%s sync would leave %s with %d owning teams, past the cap of %d; leaving its owners untouched.",
        source,
        repository_path,
        len(would_own),
        MAX_PROJECT_TEAMS,
    )
    return False


def _owner_budget(project: Project, source: str) -> int:
    """How many owners this provider may leave; handed to it, so it creates no teams for a write the cap refuses."""
    return MAX_PROJECT_TEAMS - len(set(project.team_ids) - owners_replaced_by(project, source))


def _team_subset_stages(project: Project, source: str, resolved: list[str] | None, repository_path: str) -> list[dict]:
    """This provider's ownership stages; ``None`` (not asked) writes nothing, unlike ``[]`` (no holder)."""
    if resolved is None:
        return []
    owners = sorted(set(resolved))
    owned_here = owners_replaced_by(project, source)
    if not _within_cap(source, (set(project.team_ids) - owned_here) | set(owners), repository_path):
        return []
    # Every CI job lands here; an unchanged set writes nothing unless provenance names an owner the list lacks.
    stamped = set(owners) - (set(project.team_ids) - owned_here)
    if owned_here == stamped and owned_here <= set(project.team_ids):
        return []
    return replace_team_subset_pipeline(source, owners)


async def _apply_ingest_project_update(
    project: Project,
    new_path: str,
    project_repo: ProjectRepository,
    *,
    path_field: str,
    ownership_stages: list[dict],
) -> Project:
    """Apply the rename and the resolved ownership as stages of one pipeline, so an ingest writes the project once."""
    renamed: dict = {}
    current_path = getattr(project, path_field, None)
    if current_path and current_path != new_path:
        renamed[path_field] = new_path
        if project.name == current_path:
            renamed["name"] = new_path

    if not renamed and not ownership_stages:
        return project
    await project_repo.update_fields_and_owners(project.id, renamed, ownership_stages)
    # The owners are computed server-side, so the caller is handed what was stored, not a guess.
    return await project_repo.get_by_id(project.id) or project


class _CiClaim[IdT](NamedTuple):
    external_id: IdT
    path: str
    actor: str | None


class _CiProvider[IdT: (int, str)](ABC):
    instance_field: ClassVar[str]
    id_field: ClassVar[str]
    path_field: ClassVar[str]
    allowlist_rule: ClassVar[str]
    sync_window: ClassVar[int] = 0

    service: GitLabService | GitHubService

    def key(self, external_id: IdT) -> dict[str, Any]:
        return {self.instance_field: self.service.instance_id, self.id_field: external_id}

    @abstractmethod
    async def claim(self, oidc_token: str) -> _CiClaim[IdT] | None:
        """The repository a valid token ran in, None for an invalid one, and a 403 for one the instance refuses."""

    @abstractmethod
    async def initial_member(self, claim: _CiClaim[IdT], db: AsyncIOMotorDatabase) -> str | None:
        """The local account a project created from this token gets as its admin."""

    @abstractmethod
    async def sync(
        self, db: AsyncIOMotorDatabase, claim: _CiClaim[IdT], *, current_owner_ids: set[str], owner_budget: int
    ) -> TeamSyncResult:
        """The teams holding the repository, created only within ``owner_budget``."""


class _GitLabCi(_CiProvider[int]):
    instance_field, id_field, path_field = "gitlab_instance_id", "gitlab_project_id", "gitlab_project_path"
    allowlist_rule = "auto-creation on gitlab.com needs an allowed namespace list"
    sync_window = GITLAB_TEAM_SYNC_WINDOW_SECONDS

    service: GitLabService

    def __init__(self, service: GitLabService) -> None:
        self.service = service

    async def claim(self, oidc_token: str) -> _CiClaim[int] | None:
        payload = await self.service.validate_oidc_token(oidc_token)
        if not payload:
            return None
        path = payload.project_path
        instance = self.service.instance
        if not instance.accepts_project_path(path):
            logger.warning(
                "Refused GitLab OIDC token from %s: outside the namespaces allowed on instance '%s'",
                sanitize_for_log(path),
                instance.name,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Project '{path}' is outside the namespaces allowed on GitLab instance '{instance.name}'",
            )
        return _CiClaim(int(payload.project_id), path, payload.user_email)

    async def initial_member(self, claim: _CiClaim[int], db: AsyncIOMotorDatabase) -> str | None:
        user = await UserRepository(db).get_raw_by_verified_email(claim.actor) if claim.actor else None
        return str(user["_id"]) if user else None

    async def sync(
        self, db: AsyncIOMotorDatabase, claim: _CiClaim[int], *, current_owner_ids: set[str], owner_budget: int
    ) -> TeamSyncResult:
        return await self.service.sync_team_from_gitlab(db, claim.external_id, claim.path, owner_budget=owner_budget)


class _GitHubCi(_CiProvider[str]):
    instance_field, id_field, path_field = "github_instance_id", "github_repository_id", "github_repository_path"
    allowlist_rule = "auto-creation on the shared github.com issuer needs an allowed owner list"

    service: GitHubService

    def __init__(self, service: GitHubService) -> None:
        self.service = service

    async def claim(self, oidc_token: str) -> _CiClaim[str] | None:
        payload = await self.service.validate_oidc_token(oidc_token)
        if not payload:
            return None
        instance = self.service.instance
        if not instance.accepts_owner(payload.repository_owner_id):
            logger.warning(
                "Refused GitHub OIDC token from %s (owner id %s): owner not allowed on instance '%s'",
                sanitize_for_log(payload.repository),
                sanitize_for_log(payload.repository_owner_id),
                instance.name,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Repository owner '{payload.repository_owner}' (id {payload.repository_owner_id}) "
                f"is not allowed on GitHub instance '{instance.name}'",
            )
        return _CiClaim(payload.repository_id, payload.repository, payload.actor)

    async def initial_member(self, claim: _CiClaim[str], db: AsyncIOMotorDatabase) -> str | None:
        actor = await self.service.resolve_login(claim.actor, UserRepository(db)) if claim.actor else None
        return str(actor["_id"]) if actor else None

    async def sync(
        self, db: AsyncIOMotorDatabase, claim: _CiClaim[str], *, current_owner_ids: set[str], owner_budget: int
    ) -> TeamSyncResult:
        return await self.service.sync_team_from_github(
            db, claim.path, current_owner_ids=current_owner_ids, owner_budget=owner_budget
        )


async def _ownership_stages[IdT: (int, str)](
    ci: _CiProvider[IdT], project: Project, claim: _CiClaim[IdT], db: AsyncIOMotorDatabase
) -> list[dict]:
    """The provider's ownership stages; the source is the instance that authenticated this ingest, not the project's."""
    source = ci.service.member_source
    window = f"{ci.service.team_provider}_team_sync:{source}:{claim.external_id}"
    if ci.sync_window and (await cache_service.incr(window, ci.sync_window) or 0) > 1:
        return []
    result = await ci.sync(
        db, claim, current_owner_ids=owners_replaced_by(project, source), owner_budget=_owner_budget(project, source)
    )
    return _team_subset_stages(project, source, result.team_ids, claim.path)


async def _resolve_ci_project[IdT: (int, str)](
    oidc_token: str,
    ci: _CiProvider[IdT],
    db: AsyncIOMotorDatabase,
    project_repo: ProjectRepository,
    *,
    create_missing: bool,
) -> Project:
    """``create_missing`` also renames and syncs a found project, not only creates a missing one."""
    instance = ci.service.instance
    if not instance.is_active:
        raise HTTPException(status_code=403, detail=f"{ci.service.provider} instance '{instance.name}' is not active")
    claim = await ci.claim(oidc_token)
    if claim is None:
        raise HTTPException(status_code=403, detail=f"Invalid {ci.service.provider} OIDC Token")

    key = ci.key(claim.external_id)
    project_data = await project_repo.find_one_raw(key)
    if not create_missing:
        if not project_data:
            raise HTTPException(status_code=403, detail=_MSG_CI_PROJECT_MISMATCH)
        return Project(**project_data)

    if project_data:
        project = Project(**project_data)
        stages = await _ownership_stages(ci, project, claim, db) if instance.sync_teams else []
        return await _apply_ingest_project_update(
            project, claim.path, project_repo, path_field=ci.path_field, ownership_stages=stages
        )

    not_found = f"Project not found on {ci.service.provider} instance '{instance.name}'"
    if not instance.auto_create_projects:
        raise HTTPException(status_code=404, detail=f"{not_found} and auto-creation is disabled")
    if instance.lacks_required_allowlist():
        raise HTTPException(status_code=403, detail=f"{not_found}: {ci.allowlist_rule}")

    member_id = await ci.initial_member(claim, db)
    owners: list[str] = []
    if instance.sync_teams:
        # A project being created has the whole cap to itself.
        result = await ci.sync(db, claim, current_owner_ids=set(), owner_budget=MAX_PROJECT_TEAMS)
        owners = result.team_ids or []

    new_project = Project(
        name=claim.path,
        members=[ProjectMember(user_id=member_id, role=PROJECT_ROLE_ADMIN)] if member_id else [],
        **key,
        **{ci.path_field: claim.path},
        active_analyzers=(await SystemSettingsRepository(db).get()).default_active_analyzers,
        **ownership_fields(owners, ci.service.member_source),
    )
    project, created = await project_repo.find_or_create_by_key(key, new_project)
    if created:
        logger.info("Auto-created project '%s' from %s instance '%s'", claim.path, ci.service.provider, instance.name)
    return project


async def _authenticate_via_api_key(x_api_key: str, project_repo: ProjectRepository) -> Project:
    if "." not in x_api_key:
        raise HTTPException(status_code=403, detail="Invalid API Key format")
    project_id, secret = x_api_key.split(".", 1)
    project_data = await project_repo.get_raw_by_id(project_id) or {}
    stored = project_data.get("api_key_hash")
    if not stored:
        raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)
    digest = hash_token(secret)
    if stored.startswith(_ARGON2_PREFIX):
        if not await asyncio.to_thread(security.verify_password, secret, stored):
            raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)
        # Guarded on the old hash, so a rotation that landed meanwhile is not overwritten with the old key.
        await project_repo.update_raw(project_id, {"$set": {"api_key_hash": digest}}, guard={"api_key_hash": stored})
    elif not hmac.compare_digest(digest, stored):
        raise HTTPException(status_code=403, detail=_MSG_INVALID_API_KEY)
    return Project(**project_data)


def _extract_oidc_issuer(oidc_token: str) -> str:
    if len(oidc_token.split(".")) != 3:
        raise HTTPException(status_code=403, detail="Invalid Token format. Expected a JWT (OIDC) token.")

    try:
        issuer = jwt.decode(
            oidc_token,
            options={"verify_signature": False},  # NOSONAR iss only picks the instance whose JWKS verifies the token
        ).get("iss")
    except jwt.PyJWTError as e:
        logger.warning("Undecodable OIDC token: %s", e)
        raise HTTPException(status_code=403, detail="Invalid OIDC token format") from e

    if not issuer:
        raise HTTPException(status_code=403, detail="OIDC token missing issuer (iss) claim")
    return str(issuer)


async def _authenticate_via_oidc(
    oidc_token: str, db: AsyncIOMotorDatabase, project_repo: ProjectRepository, *, create_missing: bool
) -> Project:
    issuer = _extract_oidc_issuer(oidc_token)

    if gitlab_instance := await GitLabInstanceRepository(db).get_by_url(issuer):
        gitlab = _GitLabCi(GitLabService(gitlab_instance))
        return await _resolve_ci_project(oidc_token, gitlab, db, project_repo, create_missing=create_missing)

    if github_instance := await GitHubInstanceRepository(db).get_by_url(issuer):
        github = _GitHubCi(GitHubService(github_instance))
        return await _resolve_ci_project(oidc_token, github, db, project_repo, create_missing=create_missing)

    raise HTTPException(
        status_code=403,
        detail=f"No CI/CD instance configured for OIDC issuer: {issuer}. "
        "Configure a GitLab or GitHub instance with this issuer URL.",
    )


async def _authenticate_ci(
    x_api_key: str | None, oidc_token: str | None, db: AsyncIOMotorDatabase, *, create_missing: bool
) -> Project | None:
    project_repo = ProjectRepository(db)
    if x_api_key:
        return await _authenticate_via_api_key(x_api_key, project_repo)
    if oidc_token:
        return await _authenticate_via_oidc(oidc_token, db, project_repo, create_missing=create_missing)
    return None


async def get_project_for_ingest(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    oidc_token: str | None = Header(None, alias="Job-Token"),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> Project:
    if project := await _authenticate_ci(x_api_key, oidc_token, db, create_missing=True):
        return project
    raise HTTPException(status_code=401, detail="Missing authentication credentials")


async def authorize_project_write(
    project_id: str,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    oidc_token: str | None = Header(None, alias="Job-Token"),
    token: str | None = Depends(optional_oauth2_scheme),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> str:
    from app.api.v1.helpers.projects import check_project_access

    if project := await _authenticate_ci(x_api_key, oidc_token, db, create_missing=False):
        if str(project.id) != project_id:
            raise HTTPException(status_code=403, detail=_MSG_CI_PROJECT_MISMATCH)
        return project_id

    if token:
        user = await get_current_user(db=db, token=token)
        await check_project_access(
            project_id, await get_current_active_user(user), db, required_role=PROJECT_ROLE_EDITOR
        )
        return project_id

    raise HTTPException(status_code=401, detail="Missing authentication credentials")


# A key names its surfaces; the owner's permission decides on every request whether each is still theirs.
SURFACE_PERMISSIONS: dict[str, str] = {
    API_KEY_SURFACE_MCP: Permissions.MCP_ACCESS,
    API_KEY_SURFACE_ADHOC: Permissions.ANALYZE_ADHOC,
}


# One message for unknown, revoked and expired, so a rejected token does not learn it once existed.
_MSG_UNRESOLVED_KEY = "Invalid, revoked, or expired API key"
# Naming a retired format tells the holder only what the token itself shows.
_RETIRED_KEY_PREFIXES = ("mcp_", "dca_")
_MSG_RETIRED_KEY = "This API key format is retired. Create a dck_ key under Profile > API Keys and use it instead."


def _bearer_token(authorization: str, surface: str) -> str:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": f'Bearer realm="{surface}"'},
        )
    return authorization.split(" ", 1)[1].strip()


async def _key_owner(db: AsyncIOMotorDatabase, key_doc: dict[str, Any]) -> User:
    user = await UserRepository(db).get_by_id(key_doc["user_id"])
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
) -> User:
    key_repo = ApiKeyRepository(db)
    key_doc = await key_repo.get_by_plaintext(token)
    if not key_doc:
        detail = _MSG_RETIRED_KEY if token.startswith(_RETIRED_KEY_PREFIXES) else _MSG_UNRESOLVED_KEY
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    user = await _key_owner(db, key_doc)
    if surface not in key_doc["surfaces"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key does not grant the {surface} surface",
        )
    # Answered second: a key that never named the surface must not learn what its owner holds.
    _require_permission(user, surface, permission)

    last_used_at = key_doc["last_used_at"]
    if (
        last_used_at is None
        or (datetime.now(timezone.utc) - last_used_at).total_seconds() >= API_KEY_LAST_USED_RESOLUTION_SECONDS
    ):
        await key_repo.touch_last_used(key_doc["_id"])
    return user


def require_api_key(surface: str) -> Callable[..., Awaitable[User]]:
    permission = SURFACE_PERMISSIONS[surface]

    async def dependency(
        authorization: str = Header(default=""),
        db: AsyncIOMotorDatabase = Depends(get_database),
    ) -> User:
        return await _admit_unified_key(db, _bearer_token(authorization, surface), surface, permission)

    return dependency


DatabaseDep = Annotated[AsyncIOMotorDatabase[Any], Depends(get_database)]
CurrentUserDep = Annotated[User, Depends(get_current_active_user)]
ProjectWriteDep = Annotated[str, Depends(authorize_project_write)]
AdhocKeyDep = Annotated[User, Depends(require_api_key(API_KEY_SURFACE_ADHOC))]
McpKeyDep = Annotated[User, Depends(require_api_key(API_KEY_SURFACE_MCP))]
ProjectIngestDep = Annotated[Project, Depends(get_project_for_ingest)]
SystemManagerDep = Annotated[User, Depends(PermissionChecker(Permissions.SYSTEM_MANAGE))]
