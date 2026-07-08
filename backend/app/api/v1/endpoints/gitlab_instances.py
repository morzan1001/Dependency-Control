import logging
from datetime import datetime, timezone
from typing import Annotated, Any, Dict

from fastapi import Depends, HTTPException, status

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import build_pagination_response
from app.core.permissions import Permissions
from app.models.gitlab_instance import GitLabInstance
from app.models.user import User
from app.repositories import ProjectRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.schemas.gitlab_instance import (
    GitLabInstanceCreate,
    GitLabInstanceList,
    GitLabInstanceResponse,
    GitLabInstanceTestConnectionResponse,
    GitLabInstanceUpdate,
)
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400, RESP_AUTH_400_404_500, RESP_AUTH_404
from app.services.gitlab import GitLabService

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


def _to_response(instance: GitLabInstance) -> GitLabInstanceResponse:
    return GitLabInstanceResponse(
        id=str(instance.id),
        name=instance.name,
        url=instance.url,
        description=instance.description,
        is_active=instance.is_active,
        is_default=instance.is_default,
        oidc_audience=instance.oidc_audience,
        auto_create_projects=instance.auto_create_projects,
        sync_teams=instance.sync_teams,
        team_sync_depth=getattr(instance, "team_sync_depth", 1),
        created_at=instance.created_at,
        created_by=instance.created_by,
        last_modified_at=instance.last_modified_at,
        token_configured=bool(instance.access_token),
    )


@router.get("/", response_model=GitLabInstanceList, responses=RESP_AUTH)
async def list_instances(
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
    page: int = 1,
    size: int = 100,
    active_only: bool = False,
) -> Dict[str, Any]:
    """List all GitLab instances."""
    instance_repo = GitLabInstanceRepository(db)

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
) -> GitLabInstanceResponse:
    """Get a specific GitLab instance by ID."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitLab instance with ID {instance_id} not found"
        )

    return _to_response(instance)


@router.post("/", status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_instance(
    instance_data: GitLabInstanceCreate,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitLabInstanceResponse:
    """Create a new GitLab instance after validating uniqueness and testing the connection."""
    instance_repo = GitLabInstanceRepository(db)

    if await instance_repo.exists_by_url(instance_data.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitLab instance with URL '{instance_data.url}' already exists",
        )

    if await instance_repo.exists_by_name(instance_data.name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitLab instance with name '{instance_data.name}' already exists",
        )

    new_instance = GitLabInstance(
        name=instance_data.name,
        url=instance_data.url.rstrip("/"),
        description=instance_data.description,
        is_active=instance_data.is_active,
        is_default=instance_data.is_default,
        access_token=instance_data.access_token,
        oidc_audience=instance_data.oidc_audience,
        auto_create_projects=instance_data.auto_create_projects,
        sync_teams=instance_data.sync_teams,
        team_sync_depth=instance_data.team_sync_depth,
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
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Failed to connect to GitLab instance: HTTP {response.status_code}",
                    )
        except Exception as e:
            logger.exception("Connection test failed for %s: %s", instance_data.url, e)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to connect to GitLab instance: {str(e)}"
            )

    created_instance = await instance_repo.create(new_instance)

    if created_instance.is_default:
        await instance_repo.set_as_default(str(created_instance.id))

    logger.info(f"Created GitLab instance '{created_instance.name}' by user {current_user.username}")

    return _to_response(created_instance)


@router.put("/{instance_id}", responses=RESP_AUTH_400_404_500)
async def update_instance(
    instance_id: str,
    update_data: GitLabInstanceUpdate,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitLabInstanceResponse:
    """Update a GitLab instance; only provided fields are changed, with uniqueness validation."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitLab instance with ID {instance_id} not found"
        )

    update_dict = update_data.model_dump(exclude_unset=True)

    if "url" in update_dict and update_dict["url"] != instance.url:
        if await instance_repo.exists_by_url(update_dict["url"], exclude_id=instance_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another instance with URL '{update_dict['url']}' already exists",
            )
        update_dict["url"] = update_dict["url"].rstrip("/")

    if "name" in update_dict and update_dict["name"] != instance.name:
        if await instance_repo.exists_by_name(update_dict["name"], exclude_id=instance_id):
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

    if update_dict.get("is_default"):
        await instance_repo.set_as_default(instance_id)

    updated_instance = await instance_repo.get_by_id(instance_id)
    if not updated_instance:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found after update")

    logger.info(f"Updated GitLab instance '{updated_instance.name}' by user {current_user.username}")

    return _to_response(updated_instance)


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_400_404_500)
async def delete_instance(
    instance_id: str,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
    force: bool = False,
) -> None:
    """Delete a GitLab instance; fails if projects are still linked unless force=true (which orphans them)."""
    instance_repo = GitLabInstanceRepository(db)
    project_repo = ProjectRepository(db)

    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitLab instance with ID {instance_id} not found"
        )

    project_count = await project_repo.count_by_instance(instance_id)

    if project_count > 0 and not force:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot delete instance '{instance.name}': {project_count} projects "
                f"are still linked. Set gitlab_instance_id=null on projects first "
                f"or use force=true to delete anyway."
            ),
        )

    success = await instance_repo.delete(instance_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete instance")

    logger.warning(
        f"Deleted GitLab instance '{instance.name}' by user {current_user.username} "
        f"(force={force}, orphaned_projects={project_count})"
    )


@router.post("/{instance_id}/test-connection", responses=RESP_AUTH_404)
async def test_connection(
    instance_id: str,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitLabInstanceTestConnectionResponse:
    """Test connection by calling GitLab's /version endpoint to verify connectivity and credentials."""
    instance_repo = GitLabInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitLab instance with ID {instance_id} not found"
        )

    if not instance.access_token:
        return GitLabInstanceTestConnectionResponse(
            success=False,
            message="No access token configured for this instance",
            gitlab_version=None,
            instance_name=instance.name,
            url=instance.url,
        )

    gitlab_service = GitLabService(instance)

    try:
        async with gitlab_service._api_client() as client:
            response = await client.get(f"{gitlab_service.api_url}/version", headers=gitlab_service._get_auth_headers())

            if response.status_code == 200:
                version_data = response.json()
                return GitLabInstanceTestConnectionResponse(
                    success=True,
                    message="Connection successful",
                    gitlab_version=version_data.get("version"),
                    instance_name=instance.name,
                    url=instance.url,
                )
            else:
                return GitLabInstanceTestConnectionResponse(
                    success=False,
                    message=f"GitLab API returned HTTP {response.status_code}",
                    gitlab_version=None,
                    instance_name=instance.name,
                    url=instance.url,
                )
    except Exception as e:
        logger.exception("Connection test failed for instance '%s': %s", instance.name, e)
        return GitLabInstanceTestConnectionResponse(
            success=False,
            message=f"Connection failed: {str(e)}",
            gitlab_version=None,
            instance_name=instance.name,
            url=instance.url,
        )
