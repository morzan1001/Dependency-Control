import logging
import math
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import Depends, HTTPException, status

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import build_pagination_response
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400, RESP_AUTH_400_404_500, RESP_AUTH_404
from app.core.permissions import Permissions
from app.models.github_instance import GitHubInstance
from app.models.user import User
from app.repositories import ProjectRepository
from app.repositories.github_instances import GitHubInstanceRepository
from app.schemas.github_instance import (
    GitHubInstanceCreate,
    GitHubInstanceList,
    GitHubInstanceResponse,
    GitHubInstanceTestConnectionResponse,
    GitHubInstanceUpdate,
)
from app.services.github import GitHubService

router = CustomAPIRouter()
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
        has_access_token=bool(instance.access_token),
        created_at=instance.created_at,
        created_by=instance.created_by,
        last_modified_at=instance.last_modified_at,
    )


@router.get("/", response_model=GitHubInstanceList, responses=RESP_AUTH)
async def list_instances(
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
    page: int = 1,
    size: int = 100,
    active_only: bool = False,
) -> dict[str, Any]:
    """List all GitHub instances."""
    instance_repo = GitHubInstanceRepository(db)

    skip = (page - 1) * size

    if active_only:
        instances = await instance_repo.list_active(skip=skip, limit=size)
        total = await instance_repo.count_active()
    else:
        instances = await instance_repo.list_all(skip=skip, limit=size)
        total = await instance_repo.count_all()

    items = [_to_response(instance) for instance in instances]

    return build_pagination_response(items, total, skip, size)


@router.get("/{instance_id}", responses=RESP_AUTH_404)
async def get_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitHubInstanceResponse:
    """Get a specific GitHub instance by ID."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    return _to_response(instance)


@router.post("/", status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_instance(
    instance_data: GitHubInstanceCreate,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitHubInstanceResponse:
    """Create a new GitHub instance after validating uniqueness and JWKS reachability."""
    instance_repo = GitHubInstanceRepository(db)

    if await instance_repo.exists_by_url(instance_data.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitHub instance with URL '{instance_data.url}' already exists",
        )

    if await instance_repo.exists_by_name(instance_data.name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitHub instance with name '{instance_data.name}' already exists",
        )

    new_instance = GitHubInstance(
        name=instance_data.name,
        url=instance_data.url.rstrip("/"),
        github_url=instance_data.github_url,
        description=instance_data.description,
        is_active=instance_data.is_active,
        oidc_audience=instance_data.oidc_audience,
        auto_create_projects=instance_data.auto_create_projects,
        sync_teams=instance_data.sync_teams,
        access_token=instance_data.access_token,
        created_by=str(current_user.id),
        created_at=datetime.now(timezone.utc),
    )

    # Verify JWKS reachability before saving.
    github_service = GitHubService(new_instance)
    try:
        jwks = await github_service.get_jwks()
        if not jwks or not jwks.get("keys"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OIDC endpoint reachable but returned no signing keys. Verify the issuer URL.",
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("JWKS connectivity test failed for %s: %s", instance_data.url, e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to reach OIDC endpoint: {e!s}",
        )

    created_instance = await instance_repo.create(new_instance)

    logger.info(f"Created GitHub instance '{created_instance.name}' by user {current_user.username}")

    return _to_response(created_instance)


@router.put("/{instance_id}", responses=RESP_AUTH_400_404_500)
async def update_instance(
    instance_id: str,
    update_data: GitHubInstanceUpdate,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitHubInstanceResponse:
    """Update a GitHub instance; only provided fields are changed, with uniqueness validation."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    update_dict = update_data.model_dump(exclude_unset=True)

    if "url" in update_dict and update_dict["url"] != instance.url:
        if await instance_repo.exists_by_url(update_dict["url"], exclude_id=instance_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another instance with URL '{update_dict['url']}' already exists",
            )
        update_dict["url"] = update_dict["url"].rstrip("/")

    if (
        "name" in update_dict
        and update_dict["name"] != instance.name
        and await instance_repo.exists_by_name(update_dict["name"], exclude_id=instance_id)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Another instance with name '{update_dict['name']}' already exists",
        )

    # Team syncing requires an access token.
    will_have_token = update_dict.get("access_token", instance.access_token)
    will_sync_teams = update_dict.get("sync_teams", instance.sync_teams)
    if will_sync_teams and not will_have_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An access token is required to enable team syncing",
        )

    update_dict["last_modified_at"] = datetime.now(timezone.utc)

    success = await instance_repo.update(instance_id, update_dict)

    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update instance")

    updated_instance = await instance_repo.get_by_id(instance_id)
    if not updated_instance:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found after update")

    logger.info(f"Updated GitHub instance '{updated_instance.name}' by user {current_user.username}")

    return _to_response(updated_instance)


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_400_404_500)
async def delete_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
    force: bool = False,
) -> None:
    """Delete a GitHub instance; fails if projects are still linked unless force=true (which orphans them)."""
    instance_repo = GitHubInstanceRepository(db)
    project_repo = ProjectRepository(db)

    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    project_count = await project_repo.count_by_github_instance(instance_id)

    if project_count > 0 and not force:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot delete instance '{instance.name}': {project_count} projects "
                f"are still linked. Set github_instance_id=null on projects first "
                f"or use force=true to delete anyway."
            ),
        )

    success = await instance_repo.delete(instance_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete instance")

    logger.warning(
        f"Deleted GitHub instance '{instance.name}' by user {current_user.username} "
        f"(force={force}, orphaned_projects={project_count})"
    )


def _failed_test(instance: GitHubInstance, message: str) -> GitHubInstanceTestConnectionResponse:
    return GitHubInstanceTestConnectionResponse(
        success=False,
        message=message,
        instance_name=instance.name,
        url=instance.url,
    )


async def _spent_budget_note(github_service: GitHubService) -> str | None:
    """When an exhausted core budget is what refused a probe, when it comes back; None for any other cause.

    A throttled token 403s exactly like one missing read:org, and only GET /rate_limit -- which GitHub
    does not charge -- separates them. Called on the failure path alone, so a green test costs nothing.
    """
    limit = await github_service.get_core_rate_limit()
    if limit is None or limit.remaining > 0:
        return None
    minutes = math.ceil((limit.reset_at - datetime.now(timezone.utc)).total_seconds() / 60)
    due = f"about {minutes} minute(s) from now" if minutes > 0 else "any moment now"
    return f"{limit.reset_at:%Y-%m-%d %H:%M UTC}, {due}"


async def _probe_team_access(
    github_service: GitHubService, instance: GitHubInstance
) -> GitHubInstanceTestConnectionResponse | str:
    """A failure response, or the sentence naming every organisation whose teams the token reads."""
    orgs = await github_service.get_viewer_organisations()
    # Only a refusal can be a throttle; a 200 carrying an empty list already spent budget to answer.
    if orgs is None and (reset := await _spent_budget_note(github_service)):
        return _failed_test(
            instance,
            "OIDC endpoint reachable, but the token's GitHub API rate limit is exhausted, so its "
            f"organisations could not be listed. The limit resets at {reset}. Wait for it, or stop "
            "sharing this identity with another workload; the token itself was not tested.",
        )

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
        # Exhaustion mid-loop makes every organisation after it look unreadable, so naming any of
        # them would accuse organisations the token may well be able to read.
        if reset := await _spent_budget_note(github_service):
            return _failed_test(
                instance,
                "OIDC endpoint reachable, but the token's GitHub API rate limit is exhausted, so its "
                f"team access could not be checked. The limit resets at {reset}. Wait for it, or stop "
                "sharing this identity with another workload, then test again.",
            )
        return _failed_test(
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
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitHubInstanceTestConnectionResponse:
    """Fetch the JWKS from the configured issuer and, for a team-syncing instance, exercise the token."""
    instance_repo = GitHubInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    github_service = GitHubService(instance)

    try:
        jwks = await github_service.get_jwks()

        if not jwks or not jwks.get("keys"):
            return _failed_test(instance, "JWKS endpoint returned no signing keys")

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
