import logging
from typing import Annotated, Any

import httpx
from fastapi import HTTPException, Query, status

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import (
    RESP_AUTH,
    RESP_AUTH_400,
    RESP_AUTH_400_404_500,
    RESP_AUTH_404,
    RESP_AUTH_404_502,
)
from app.api.v1.helpers.vcs_instances import (
    apply_update,
    assert_unique,
    delete_guarded,
    get_or_404,
    list_page,
    signing_key_check,
)
from app.core.constants import TEAM_SOURCE_GITLAB
from app.models.gitlab_instance import GitLabInstance
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.schemas.gitlab_instance import (
    AUTO_CREATE_NEEDS_NAMESPACES,
    GitLabGroupOption,
    GitLabInstanceCreate,
    GitLabInstanceResponse,
    GitLabInstanceTestConnectionResponse,
    GitLabInstanceUpdate,
)
from app.schemas.pagination import Page
from app.services.gitlab import GitLabService, build_group_options

router = CustomAPIRouter()
_LABEL = "GitLab"
logger = logging.getLogger(__name__)


def _to_response(instance: GitLabInstance) -> GitLabInstanceResponse:
    return GitLabInstanceResponse(**instance.model_dump(), token_configured=bool(instance.access_token))


@router.get("/", response_model=Page[GitLabInstanceResponse], responses=RESP_AUTH)
async def list_instances(
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 100,
    active_only: bool = False,
) -> dict[str, Any]:
    """List all GitLab instances."""
    return await list_page(GitLabInstanceRepository(db), page, size, active_only, _to_response)


@router.get("/{instance_id}", responses=RESP_AUTH_404)
async def get_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitLabInstanceResponse:
    """Get a specific GitLab instance by ID."""
    return _to_response(await get_or_404(GitLabInstanceRepository(db), instance_id, _LABEL))


@router.post("/", status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_instance(
    instance_data: GitLabInstanceCreate,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitLabInstanceResponse:
    """Create a new GitLab instance after validating uniqueness and a configured token."""
    instance_repo = GitLabInstanceRepository(db)

    await assert_unique(instance_repo, _LABEL, url=instance_data.url, name=instance_data.name)

    new_instance = GitLabInstance(**instance_data.model_dump(), created_by=str(current_user.id))
    if new_instance.access_token:
        try:
            response = await GitLabService(new_instance).get_version()
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
    updated = await apply_update(
        instance_repo, instance_id, update_data, _LABEL, current_user.username, AUTO_CREATE_NEEDS_NAMESPACES
    )
    return _to_response(updated)


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


async def _probe_group_access(gitlab_service: GitLabService) -> tuple[bool, str]:
    """The token's visible groups are all team sync can resolve, so one that reads none must fail the test."""
    response = await gitlab_service._api_get("/groups", params={"per_page": 1})
    try:
        groups = response.json() if response is not None and response.status_code == 200 else None
    except ValueError:
        groups = None
    if response is None or not isinstance(groups, list):
        return False, (
            "The token could not list groups. Team sync resolves a project's group through this listing, so it "
            "needs a token with the read_api or api scope. Until then no repository on this instance gets a team."
        )
    if not groups:
        return False, (
            "The token belongs to no group. GitLab scopes the group listing to the token's own memberships, so "
            "team sync needs an identity that is a member of the groups DependencyControl covers, or an "
            "administrator token."
        )
    # GitLab withholds the total past 10,000 rows.
    total = response.headers.get("x-total")
    return True, f"Token reads {total} group(s)." if total else "Token reads at least one group."


@router.post("/{instance_id}/test-connection", responses=RESP_AUTH_404)
async def test_connection(
    instance_id: str,
    db: DatabaseDep,
    current_user: deps.SystemManagerDep,
) -> GitLabInstanceTestConnectionResponse:
    """Fetch the JWKS from the instance, try a configured token, and check a team-syncing one's group access."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await get_or_404(instance_repo, instance_id, _LABEL)

    gitlab_service = GitLabService(instance)

    try:
        jwks_ok, message = await signing_key_check(gitlab_service)
        if not instance.access_token:
            return _test_result(instance, success=jwks_ok, message=message)
        if not jwks_ok:
            # The token still serves MR decoration and branch and team sync without the keys.
            message = f"Warning: {message}, so OIDC job tokens from this instance fail validation."
        response = await gitlab_service.get_version()
        if response.status_code != 200:
            return _test_result(
                instance,
                success=False,
                message=f"{message} The GitLab API returned HTTP {response.status_code} for the access token.",
            )
        version = response.json().get("version")
        message += " The access token authenticates."
        # Only a team-syncing instance needs group access; a pure-ingest one would fail a good setup.
        if instance.sync_teams:
            groups_ok, groups_message = await _probe_group_access(gitlab_service)
            message += f" {groups_message}"
            if not groups_ok:
                return _test_result(instance, success=False, message=message, version=version)

        return _test_result(instance, success=True, message=message, version=version)
    except Exception as e:
        logger.exception("Connection test failed for instance '%s': %s", instance.name, e)
        return _test_result(instance, success=False, message=f"Connection failed: {e!s}")
