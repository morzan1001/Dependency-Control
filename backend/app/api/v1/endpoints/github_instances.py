import asyncio
import logging
from typing import Annotated, Any

from fastapi import Query, status

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.vcs_instances import (
    TOKEN_CHECK_HINT,
    Refusal,
    apply_update,
    assert_unique,
    delete_guarded,
    get_or_404,
    list_page,
    refused_listing,
    require_signing_keys,
    undetermined,
    why_refused,
)
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
)
from app.schemas.pagination import Page
from app.services.github import GitHubService, build_org_team_options

router = CustomAPIRouter()
_LABEL = "GitHub"
logger = logging.getLogger(__name__)


def _to_response(instance: GitHubInstance) -> GitHubInstanceResponse:
    return GitHubInstanceResponse(**instance.model_dump(), token_configured=bool(instance.access_token))


@router.get("/", response_model=Page[GitHubInstanceResponse], responses=RESP_AUTH)
async def list_instances(
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 100,
    active_only: bool = False,
) -> dict[str, Any]:
    """List all GitHub instances."""
    return await list_page(GitHubInstanceRepository(db), page, size, active_only, _to_response)


@router.get("/{instance_id}", responses=RESP_AUTH_404)
async def get_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitHubInstanceResponse:
    """Get a specific GitHub instance by ID."""
    return _to_response(await get_or_404(GitHubInstanceRepository(db), instance_id, _LABEL))


@router.post("/", status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_instance(
    instance_data: GitHubInstanceCreate,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitHubInstanceResponse:
    """Create a new GitHub instance after validating uniqueness and JWKS reachability."""
    instance_repo = GitHubInstanceRepository(db)

    await assert_unique(instance_repo, _LABEL, url=instance_data.url, name=instance_data.name)

    new_instance = GitHubInstance(**instance_data.model_dump(), created_by=str(current_user.id))
    await require_signing_keys(GitHubService(new_instance))

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
    updated = await apply_update(
        instance_repo, instance_id, update_data, _LABEL, current_user.username, AUTO_CREATE_NEEDS_OWNERS
    )
    return _to_response(updated)


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
        raise await refused_listing(
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
        raise await refused_listing(
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


def _budget_failure(instance: GitHubInstance, blocked: str, reset: str) -> GitHubInstanceTestConnectionResponse:
    return _failed_test(
        instance,
        f"OIDC endpoint reachable, but the token's GitHub API rate limit is exhausted, so {blocked}. The limit "
        f"resets at {reset}. Wait for it, or stop sharing this identity with another workload, then test again.",
    )


async def _probe_token(
    github_service: GitHubService, instance: GitHubInstance
) -> GitHubInstanceTestConnectionResponse | str:
    if github_service.api_url is None:
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the access token is sent nowhere: a GitHub Enterprise instance "
            "names its API host only through the GitHub web URL. Set it, or pull-request decoration and "
            "branch housekeeping never call the API.",
        )
    response = await github_service._api_get("/user")
    if response is not None and response.status_code == 200:
        return " The access token authenticates."
    cause, reset = await why_refused(github_service)
    if cause is Refusal.BUDGET:
        return _budget_failure(instance, "the token could not be tried", reset)
    if response is not None and response.status_code in (401, 403):
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but GitHub refused the access token on GET /user, so pull-request "
            f"decoration, branch housekeeping and team sync cannot use it. {TOKEN_CHECK_HINT}",
        )
    answer = "got no answer" if response is None else f"answered HTTP {response.status_code}"
    return _failed_test(
        instance,
        f"OIDC endpoint reachable, but GET /user {answer}, so whether GitHub accepts the access token could "
        "not be determined: the API host may be unreachable, or GitHub may be failing. Check both, then test again.",
    )


async def _refused_probe(
    github_service: GitHubService, instance: GitHubInstance, blocked: str
) -> GitHubInstanceTestConnectionResponse | None:
    """None when the budget stands and GitHub took the token, so the refusal was the missing read:org."""
    cause, reset = await why_refused(github_service)
    if cause is Refusal.BUDGET:
        return _budget_failure(instance, f"its {blocked}", reset)
    if cause is Refusal.CREDENTIALS:
        return _failed_test(
            instance,
            f"OIDC endpoint reachable, but GitHub refused the access token, so its {blocked}. {TOKEN_CHECK_HINT}",
        )
    if cause is Refusal.UNDETERMINED:
        failure = f"OIDC endpoint reachable, but the token's {blocked}"
        return _failed_test(instance, f"{undetermined(failure)}, then test again.")
    return None


async def _probe_team_access(
    github_service: GitHubService, instance: GitHubInstance
) -> GitHubInstanceTestConnectionResponse | str:
    orgs = await github_service.get_viewer_organisations()
    # Only a refusal can be a throttle; a 200 carrying an empty list already spent budget to answer.
    if orgs is None and (
        refused := await _refused_probe(github_service, instance, "organisations could not be listed")
    ):
        return refused

    org_names = [str(org["login"]) for org in orgs if org.get("login")] if orgs else []
    if not org_names:
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the token cannot list its organisations. "
            "Team sync needs read:org and an identity that is a member of the "
            "organisation, or it will silently see only part of it.",
        )

    # Team sync acts on every organisation of the token, so one unreadable organisation fails the test.
    counts = await asyncio.gather(*(github_service.count_org_teams(name) for name in org_names))
    probes = list(zip(org_names, counts, strict=True))
    unreadable = [name for name, count in probes if count is None]
    if unreadable:
        # Exhaustion during the probes fails readable organisations too, so none of the failed ones is named.
        return await _refused_probe(github_service, instance, "team access could not be checked") or _failed_test(
            instance,
            "OIDC endpoint reachable, but the token cannot read teams in "
            f"{', '.join(unreadable)}. Every organisation the token belongs to is "
            "probed, so either grant it read:org there, or use a dedicated identity "
            "that belongs only to the organisations DependencyControl covers. "
            "Until then repositories there get partial or no teams.",
        )

    covered = ", ".join(f"{name} ({count} team(s))" for name, count in probes)
    return f" Token reads teams in {covered}."


@router.post("/{instance_id}/test-connection", responses=RESP_AUTH_404)
async def test_connection(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitHubInstanceTestConnectionResponse:
    """Fetch the JWKS from the configured issuer, try a configured token, and check a team-syncing one's team access."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    github_service = GitHubService(instance)

    try:
        jwks = await github_service.refresh_jwks()

        if not jwks or not jwks.get("keys"):
            return _failed_test(instance, "JWKS endpoint unreachable or returned no signing keys")

        message = f"OIDC endpoint reachable. Found {len(jwks['keys'])} signing key(s)."
        if instance.access_token:
            token_check = await _probe_token(github_service, instance)
            if isinstance(token_check, GitHubInstanceTestConnectionResponse):
                return token_check
            message += token_check
        # Only a team-syncing instance needs organisation access; a pure-ingest one would fail a good setup.
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
