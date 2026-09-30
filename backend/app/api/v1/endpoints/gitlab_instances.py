import logging
from datetime import datetime, timezone
from typing import Annotated, Any

import httpx
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
from app.core.constants import TEAM_SOURCE_GITLAB
from app.models.gitlab_instance import GitLabInstance
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.schemas.gitlab_instance import (
    AUTO_CREATE_NEEDS_NAMESPACES,
    GitLabGroupOption,
    GitLabInstanceCreate,
    GitLabInstanceList,
    GitLabInstanceResponse,
    GitLabInstanceTestConnectionResponse,
    GitLabInstanceUpdate,
    lacks_required_namespaces,
)
from app.services.gitlab import GitLabService, build_group_options

router = CustomAPIRouter()
_LABEL = "GitLab"
logger = logging.getLogger(__name__)


def _to_response(instance: GitLabInstance) -> GitLabInstanceResponse:
    return GitLabInstanceResponse(
        id=str(instance.id),
        name=instance.name,
        url=instance.url,
        description=instance.description,
        is_active=instance.is_active,
        oidc_audience=instance.oidc_audience,
        auto_create_projects=instance.auto_create_projects,
        sync_teams=instance.sync_teams,
        team_sync_depth=getattr(instance, "team_sync_depth", 1),
        allowed_namespaces=instance.allowed_namespaces,
        created_at=instance.created_at,
        created_by=instance.created_by,
        last_modified_at=instance.last_modified_at,
        token_configured=bool(instance.access_token),
    )


@router.get("/", response_model=GitLabInstanceList, responses=RESP_AUTH)
async def list_instances(
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 100,
    active_only: bool = False,
) -> dict[str, Any]:
    """List all GitLab instances."""
    instance_repo = GitLabInstanceRepository(db)

    instances, total, skip = await list_page(instance_repo, page, size, active_only)
    items = [_to_response(instance) for instance in instances]

    return build_pagination_response(items, total, skip, size)


@router.get("/{instance_id}", responses=RESP_AUTH_404)
async def get_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitLabInstanceResponse:
    """Get a specific GitLab instance by ID."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    return _to_response(instance)


@router.post("/", status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_instance(
    instance_data: GitLabInstanceCreate,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitLabInstanceResponse:
    """Create a new GitLab instance after validating uniqueness and testing the connection."""
    instance_repo = GitLabInstanceRepository(db)

    await assert_unique(instance_repo, _LABEL, url=instance_data.url, name=instance_data.name)

    new_instance = GitLabInstance(
        name=instance_data.name,
        url=instance_data.url,
        description=instance_data.description,
        is_active=instance_data.is_active,
        access_token=instance_data.access_token,
        oidc_audience=instance_data.oidc_audience,
        auto_create_projects=instance_data.auto_create_projects,
        sync_teams=instance_data.sync_teams,
        team_sync_depth=instance_data.team_sync_depth,
        allowed_namespaces=instance_data.allowed_namespaces,
        created_by=str(current_user.id),
        created_at=datetime.now(timezone.utc),
    )

    if new_instance.access_token:
        gitlab_service = GitLabService(new_instance)
        try:
            async with gitlab_service._api_client() as client:
                response = await client.get(
                    f"{gitlab_service.api_url}/version", headers=gitlab_service._get_auth_headers()
                )
        except (httpx.HTTPError, httpx.InvalidURL) as e:
            logger.warning("Connection test failed for %s: %s", instance_data.url, e)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to connect to GitLab instance: {e!s}"
            ) from e
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to connect to GitLab instance: HTTP {response.status_code}",
            )

    created_instance = await instance_repo.create(new_instance)
    logger.info(f"Created GitLab instance '{created_instance.name}' by user {current_user.username}")

    return _to_response(created_instance)


@router.put("/{instance_id}", responses=RESP_AUTH_400_404_500)
async def update_instance(
    instance_id: str,
    update_data: GitLabInstanceUpdate,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitLabInstanceResponse:
    """Update a GitLab instance; only provided fields are changed, with uniqueness validation."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    update_dict = update_data.model_dump(exclude_unset=True)
    await prepare_update(instance_repo, instance, update_dict)

    if lacks_required_namespaces(
        update_dict.get("url", instance.url),
        update_dict.get("auto_create_projects", instance.auto_create_projects),
        update_dict.get("allowed_namespaces", instance.allowed_namespaces),
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=AUTO_CREATE_NEEDS_NAMESPACES)

    updated_instance = await instance_repo.update(instance_id, update_dict)
    if not updated_instance:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found after update")

    logger.info(f"Updated GitLab instance '{updated_instance.name}' by user {current_user.username}")

    return _to_response(updated_instance)


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_400_404_500)
async def delete_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> None:
    """Delete a GitLab instance no project links to, with its team bindings and the members its sync added."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    await delete_guarded(db, instance_repo, instance, provider=TEAM_SOURCE_GITLAB, username=current_user.username)


@router.get("/{instance_id}/groups", responses=RESP_AUTH_404_502)
async def list_instance_groups(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
    search: str | None = None,
) -> list[GitLabGroupOption]:
    """The groups this instance's token can see, to pick from when binding a team."""
    instance = await get_or_404(GitLabInstanceRepository(db), instance_id, _LABEL)

    groups = await GitLabService(instance).get_groups(search)
    if groups is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Could not list the groups of instance '{instance.name}'. It needs an access token that can read them."
            ),
        )
    return build_group_options(groups)


def _test_result(
    instance: GitLabInstance,
    *,
    success: bool,
    message: str,
    version: str | None = None,
) -> GitLabInstanceTestConnectionResponse:
    return GitLabInstanceTestConnectionResponse(
        success=success,
        message=message,
        gitlab_version=version,
        instance_name=instance.name,
        url=instance.url,
    )


async def _probe_group_access(
    gitlab_service: GitLabService, instance: GitLabInstance, version: str | None
) -> GitLabInstanceTestConnectionResponse | str:
    """A failure response, or the sentence saying how many groups the token reads.

    The groups it can see are exactly the groups team sync can resolve, so a token that reads none
    syncs nothing — and a green test that hides that sends the operator looking elsewhere for weeks.
    """
    groups = await gitlab_service.get_groups()
    if groups is None:
        return _test_result(
            instance,
            success=False,
            version=version,
            message=(
                "Connection successful, but the token could not list groups. Team sync resolves a "
                "project's group through this listing, so it needs a token with the read_api or api "
                "scope. Until then no repository on this instance gets a team."
            ),
        )
    if not groups:
        return _test_result(
            instance,
            success=False,
            version=version,
            message=(
                "Connection successful, but the token belongs to no group. GitLab scopes the group "
                "listing to the token's own memberships, so team sync needs an identity that is a "
                "member of the groups DependencyControl covers, or an administrator token."
            ),
        )
    return f" Token reads {len(groups)} group(s)."


@router.post("/{instance_id}/test-connection", responses=RESP_AUTH_404)
async def test_connection(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitLabInstanceTestConnectionResponse:
    """Call GitLab's /version endpoint and, for a team-syncing instance, exercise the token's group access."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    if not instance.access_token:
        return _test_result(instance, success=False, message="No access token configured for this instance")

    gitlab_service = GitLabService(instance)

    try:
        async with gitlab_service._api_client() as client:
            response = await client.get(f"{gitlab_service.api_url}/version", headers=gitlab_service._get_auth_headers())

        if response.status_code != 200:
            return _test_result(instance, success=False, message=f"GitLab API returned HTTP {response.status_code}")

        version = response.json().get("version")
        message = "Connection successful"
        # Only an instance that syncs teams needs group access; demanding it of a pure-ingest
        # instance would fail a perfectly good setup.
        if instance.sync_teams:
            probe = await _probe_group_access(gitlab_service, instance, version)
            if isinstance(probe, GitLabInstanceTestConnectionResponse):
                return probe
            message += probe

        return _test_result(instance, success=True, message=message, version=version)
    except Exception as e:
        logger.exception("Connection test failed for instance '%s': %s", instance.name, e)
        return _test_result(instance, success=False, message=f"Connection failed: {e!s}")
