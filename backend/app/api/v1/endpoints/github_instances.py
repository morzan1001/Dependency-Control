import logging
import math
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Annotated, Any

from fastapi import HTTPException, Query, status

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import build_pagination_response
from app.api.v1.helpers.vcs_instances import assert_unique, delete_guarded, get_or_404, list_page, prepare_update
from app.api.v1.helpers.responses import (
    RESP_AUTH,
    RESP_AUTH_400,
    RESP_AUTH_400_404_500,
    RESP_AUTH_404,
    RESP_AUTH_404_502,
)
from app.core.constants import TEAM_SOURCE_GITHUB
from app.models.github_instance import GitHubInstance
from app.repositories.github_instances import GitHubInstanceRepository
from app.schemas.github_instance import (
    AUTO_CREATE_NEEDS_OWNERS,
    GitHubInstanceCreate,
    GitHubInstanceResponse,
    GitHubInstanceTestConnectionResponse,
    GitHubInstanceUpdate,
    GitHubOrgTeam,
    lacks_required_owners,
)
from app.schemas.pagination import Page
from app.services.github import GitHubService, build_org_team_options

router = CustomAPIRouter()
_LABEL = "GitHub"
logger = logging.getLogger(__name__)


def _to_response(instance: GitHubInstance) -> GitHubInstanceResponse:
    return GitHubInstanceResponse(
        id=str(instance.id),
        name=instance.name,
        url=instance.url,
        github_url=instance.github_url,
        description=instance.description,
        is_active=instance.is_active,
        oidc_audience=instance.oidc_audience,
        auto_create_projects=instance.auto_create_projects,
        sync_teams=instance.sync_teams,
        allowed_owner_ids=instance.allowed_owner_ids,
        token_configured=bool(instance.access_token),
        created_at=instance.created_at,
        created_by=instance.created_by,
        last_modified_at=instance.last_modified_at,
    )


@router.get("/", response_model=Page[GitHubInstanceResponse], responses=RESP_AUTH)
async def list_instances(
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 100,
    active_only: bool = False,
) -> dict[str, Any]:
    """List all GitHub instances."""
    instance_repo = GitHubInstanceRepository(db)

    instances, total, skip = await list_page(instance_repo, page, size, active_only)
    items = [_to_response(instance) for instance in instances]

    return build_pagination_response(items, total, skip, size)


@router.get("/{instance_id}", responses=RESP_AUTH_404)
async def get_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitHubInstanceResponse:
    """Get a specific GitHub instance by ID."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    return _to_response(instance)


@router.post("/", status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_instance(
    instance_data: GitHubInstanceCreate,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitHubInstanceResponse:
    """Create a new GitHub instance after validating uniqueness and JWKS reachability."""
    instance_repo = GitHubInstanceRepository(db)

    await assert_unique(instance_repo, _LABEL, url=instance_data.url, name=instance_data.name)

    new_instance = GitHubInstance(
        name=instance_data.name,
        url=instance_data.url,
        github_url=instance_data.github_url,
        description=instance_data.description,
        is_active=instance_data.is_active,
        oidc_audience=instance_data.oidc_audience,
        auto_create_projects=instance_data.auto_create_projects,
        sync_teams=instance_data.sync_teams,
        access_token=instance_data.access_token,
        allowed_owner_ids=instance_data.allowed_owner_ids,
        created_by=str(current_user.id),
        created_at=datetime.now(timezone.utc),
    )

    jwks = await GitHubService(new_instance).get_jwks()
    if not jwks or not jwks.get("keys"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC endpoint unreachable or returned no signing keys. Verify the issuer URL.",
        )

    created_instance = await instance_repo.create(new_instance)

    logger.info(f"Created GitHub instance '{created_instance.name}' by user {current_user.username}")

    return _to_response(created_instance)


@router.put("/{instance_id}", responses=RESP_AUTH_400_404_500)
async def update_instance(
    instance_id: str,
    update_data: GitHubInstanceUpdate,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitHubInstanceResponse:
    """Update a GitHub instance; only provided fields are changed, with uniqueness validation."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    update_dict = update_data.model_dump(exclude_unset=True)
    await prepare_update(instance_repo, instance, update_dict)

    if lacks_required_owners(
        update_dict.get("url", instance.url),
        update_dict.get("auto_create_projects", instance.auto_create_projects),
        update_dict.get("allowed_owner_ids", instance.allowed_owner_ids),
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=AUTO_CREATE_NEEDS_OWNERS)

    updated_instance = await instance_repo.update(instance_id, update_dict)
    if not updated_instance:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found after update")

    logger.info(f"Updated GitHub instance '{updated_instance.name}' by user {current_user.username}")

    return _to_response(updated_instance)


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_400_404_500)
async def delete_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> None:
    """Delete a GitHub instance no project links to, with its team bindings and the members its sync added."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    await delete_guarded(db, instance_repo, instance, provider=TEAM_SOURCE_GITHUB, username=current_user.username)


class _Refusal(Enum):
    """What turned a GitHub read into a refusal, as far as the budget reading can establish."""

    BUDGET = auto()
    SCOPE = auto()
    UNDETERMINED = auto()


async def _why_refused(github_service: GitHubService) -> tuple[_Refusal, str]:
    """What refused a read, and -- when the budget did -- the moment it comes back.

    A throttled token 403s exactly like one missing read:org, and only GET /rate_limit -- which GitHub
    does not charge -- separates them. Called on a failure path alone, so a green read costs nothing.
    """
    limit = await github_service.get_core_rate_limit()
    if limit is None:
        return _Refusal.UNDETERMINED, ""
    if limit.remaining > 0:
        return _Refusal.SCOPE, ""
    minutes = math.ceil((limit.reset_at - datetime.now(timezone.utc)).total_seconds() / 60)
    due = f"about {minutes} minute(s) from now" if minutes > 0 else "any moment now"
    return _Refusal.BUDGET, f"{limit.reset_at:%Y-%m-%d %H:%M UTC}, {due}"


async def _refused_listing(github_service: GitHubService, subject: str, scope_hint: str) -> HTTPException:
    """The 502 for a picker listing GitHub refused, naming what refused rather than assuming the scope."""
    cause, reset = await _why_refused(github_service)
    if cause is _Refusal.BUDGET:
        detail = (
            f"Could not list {subject}: the token's GitHub API rate limit is exhausted. The limit resets at {reset}."
        )
    elif cause is _Refusal.SCOPE:
        detail = f"Could not list {subject}. {scope_hint}"
    else:
        detail = (
            f"Could not list {subject}, and GET /rate_limit did not answer either, so whether an "
            "exhausted rate limit or a missing read:org refused could not be determined. Check both."
        )
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)


@router.get("/{instance_id}/orgs", responses=RESP_AUTH_404_502)
async def list_instance_organisations(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> list[str]:
    """The organisations this instance's token belongs to, to pick from when binding a team."""
    instance = await get_or_404(GitHubInstanceRepository(db), instance_id, _LABEL)
    github_service = GitHubService(instance)
    orgs = await github_service.get_viewer_organisations()
    if orgs is None:
        raise await _refused_listing(
            github_service,
            f"the organisations of instance '{instance.name}'",
            "The token needs read:org.",
        )
    return [str(org["login"]) for org in orgs if org.get("login")]


@router.get("/{instance_id}/orgs/{org}/teams", responses=RESP_AUTH_404_502)
async def list_organisation_teams(
    instance_id: str,
    org: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> list[GitHubOrgTeam]:
    """The teams of one organisation, to pick from when binding a team."""
    instance = await get_or_404(GitHubInstanceRepository(db), instance_id, _LABEL)
    github_service = GitHubService(instance)
    org_teams = await github_service.get_org_teams(org)
    if org_teams is None:
        raise await _refused_listing(
            github_service,
            f"the teams of organisation '{org}'",
            "The token needs read:org there.",
        )
    return build_org_team_options(org_teams)


def _failed_test(instance: GitHubInstance, message: str) -> GitHubInstanceTestConnectionResponse:
    return GitHubInstanceTestConnectionResponse(
        success=False,
        message=message,
        instance_name=instance.name,
        url=instance.url,
    )


async def _refused_org_listing(
    github_service: GitHubService, instance: GitHubInstance
) -> GitHubInstanceTestConnectionResponse | None:
    """The failure the org probe's refusal established, or None to leave it to the scope message."""
    cause, reset = await _why_refused(github_service)
    if cause is _Refusal.BUDGET:
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the token's GitHub API rate limit is exhausted, so its "
            f"organisations could not be listed. The limit resets at {reset}. Wait for it, or stop "
            "sharing this identity with another workload; the token itself was not tested.",
        )
    if cause is _Refusal.UNDETERMINED:
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the token could not list its organisations, and "
            "GET /rate_limit did not answer either, so whether an exhausted rate limit or a missing "
            "read:org refused could not be determined. Check both, then test again.",
        )
    return None


async def _refused_team_listing(
    github_service: GitHubService, instance: GitHubInstance, unreadable: list[str]
) -> GitHubInstanceTestConnectionResponse:
    """The failure behind an organisation whose teams went unread, accusing only what was established."""
    cause, reset = await _why_refused(github_service)
    # Exhaustion mid-loop makes every organisation after it look unreadable, so naming any of them
    # would accuse organisations the token may well be able to read.
    if cause is _Refusal.BUDGET:
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the token's GitHub API rate limit is exhausted, so its "
            f"team access could not be checked. The limit resets at {reset}. Wait for it, or stop "
            "sharing this identity with another workload, then test again.",
        )
    if cause is _Refusal.UNDETERMINED:
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the token's team access could not be checked, and "
            "GET /rate_limit did not answer either, so whether an exhausted rate limit or a missing "
            "read:org refused could not be determined. Check both, then test again.",
        )
    return _failed_test(
        instance,
        "OIDC endpoint reachable, but the token cannot read teams in "
        f"{', '.join(unreadable)}. Every organisation the token belongs to is "
        "probed, so either grant it read:org there, or use a dedicated identity "
        "that belongs only to the organisations DependencyControl covers. "
        "Until then repositories there get partial or no teams.",
    )


async def _probe_team_access(
    github_service: GitHubService, instance: GitHubInstance
) -> GitHubInstanceTestConnectionResponse | str:
    """A failure response, or the sentence naming every organisation whose teams the token reads."""
    orgs = await github_service.get_viewer_organisations()
    # Only a refusal can be a throttle; a 200 carrying an empty list already spent budget to answer.
    if orgs is None and (refused := await _refused_org_listing(github_service, instance)):
        return refused

    org_names = [str(org["login"]) for org in orgs if org.get("login")] if orgs else []
    if not org_names:
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the token cannot list its organisations. "
            "Team sync needs read:org and an identity that is a member of the "
            "organisation, or it will silently see only part of it.",
        )

    # Every organisation the token belongs to is one team sync will act on, so a single
    # unreadable one is a red test: a green one hiding it is the §8 partial-team failure.
    probes = [(name, await github_service.count_org_teams(name)) for name in org_names]
    unreadable = [name for name, count in probes if count is None]
    if unreadable:
        return await _refused_team_listing(github_service, instance, unreadable)

    covered = ", ".join(f"{name} ({count} team(s))" for name, count in probes)
    return f" Token reads teams in {covered}."


@router.post("/{instance_id}/test-connection", responses=RESP_AUTH_404)
async def test_connection(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitHubInstanceTestConnectionResponse:
    """Fetch the JWKS from the configured issuer and, for a team-syncing instance, exercise the token."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    github_service = GitHubService(instance)

    try:
        jwks = await github_service.refresh_jwks()

        if not jwks or not jwks.get("keys"):
            return _failed_test(instance, "JWKS endpoint unreachable or returned no signing keys")

        message = f"OIDC endpoint reachable. Found {len(jwks['keys'])} signing key(s)."
        # Only an instance that syncs teams needs organisation access; demanding it of a
        # pure-ingest instance would fail a perfectly good setup.
        if instance.sync_teams:
            team_access = await _probe_team_access(github_service, instance)
            if isinstance(team_access, GitHubInstanceTestConnectionResponse):
                return team_access
            message += team_access

        return GitHubInstanceTestConnectionResponse(
            success=True,
            message=message,
            instance_name=instance.name,
            url=instance.url,
        )
    except Exception as e:
        logger.exception("Connection test failed for GitHub instance '%s': %s", instance.name, e)
        return _failed_test(instance, f"Connection failed: {e!s}")
