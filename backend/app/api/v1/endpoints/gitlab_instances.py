import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import build_pagination_response
from app.db.mongodb import get_database
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
from app.services.gitlab import GitLabService

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


def _to_response(instance: GitLabInstance) -> GitLabInstanceResponse:
    """Convert GitLabInstance to response schema."""
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
        created_at=instance.created_at,
        created_by=instance.created_by,
        last_modified_at=instance.last_modified_at,
        token_configured=bool(instance.access_token),
    )


@router.get("/", response_model=GitLabInstanceList)
async def list_instances(
    page: int = 1,
    size: int = 100,
    active_only: bool = False,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    List all GitLab instances.
    Requires system:manage permission.
    """
    instance_repo = GitLabInstanceRepository(db)

    skip = (page - 1) * size

    if active_only:
        instances = await instance_repo.list_active(skip=skip, limit=size)
        total = await instance_repo.count_active()
    else:
        instances = await instance_repo.list_all(skip=skip, limit=size)
        total = await instance_repo.count_all()

    items = [_to_response(instance) for instance in instances]

    return build_pagination_response(items, total, page, size)


@router.get("/{instance_id}", response_model=GitLabInstanceResponse)
async def get_instance(
    instance_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Get a specific GitLab instance by ID.
    Requires system:manage permission.
    """
    instance_repo = GitLabInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GitLab instance with ID {instance_id} not found"
        )

    return _to_response(instance)


@router.post("/", response_model=GitLabInstanceResponse, status_code=status.HTTP_201_CREATED)
async def create_instance(
    instance_data: GitLabInstanceCreate,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Create a new GitLab instance.
    Requires system:manage permission.

    - Validates that URL and name are unique
    - Tests connection before creating
    """
    instance_repo = GitLabInstanceRepository(db)

    # Validate URL uniqueness
    if await instance_repo.exists_by_url(instance_data.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitLab instance with URL '{instance_data.url}' already exists"
        )

    # Validate name uniqueness
    if await instance_repo.exists_by_name(instance_data.name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitLab instance with name '{instance_data.name}' already exists"
        )

    # Create instance object
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
        created_by=str(current_user.id),
        created_at=datetime.now(timezone.utc),
    )

    # Test connection before saving
    gitlab_service = GitLabService(new_instance)
    try:
        async with gitlab_service._api_client() as client:
            response = await client.get(
                f"{gitlab_service.api_url}/version",
                headers=gitlab_service._get_auth_headers()
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to connect to GitLab instance: HTTP {response.status_code}"
                )
    except Exception as e:
        logger.error(f"Connection test failed for {instance_data.url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect to GitLab instance: {str(e)}"
        )

    # Save to database
    created_instance = await instance_repo.create(new_instance)

    # If this is set as default, ensure no other instance is default
    if created_instance.is_default:
        await instance_repo.set_as_default(str(created_instance.id))

    logger.info(f"Created GitLab instance '{created_instance.name}' by user {current_user.username}")

    return _to_response(created_instance)


@router.put("/{instance_id}", response_model=GitLabInstanceResponse)
async def update_instance(
    instance_id: str,
    update_data: GitLabInstanceUpdate,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Update a GitLab instance.
    Requires system:manage permission.

    - Only updates provided fields
    - Validates uniqueness constraints
    """
    instance_repo = GitLabInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GitLab instance with ID {instance_id} not found"
        )

    # Build update dict (only non-None values)
    update_dict = update_data.model_dump(exclude_unset=True)

    # Validate URL uniqueness if changing URL
    if "url" in update_dict and update_dict["url"] != instance.url:
        if await instance_repo.exists_by_url(update_dict["url"], exclude_id=instance_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another instance with URL '{update_dict['url']}' already exists"
            )
        # Normalize URL
        update_dict["url"] = update_dict["url"].rstrip("/")

    # Validate name uniqueness if changing name
    if "name" in update_dict and update_dict["name"] != instance.name:
        if await instance_repo.exists_by_name(update_dict["name"], exclude_id=instance_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another instance with name '{update_dict['name']}' already exists"
            )

    # Add last_modified metadata
    update_dict["last_modified_at"] = datetime.now(timezone.utc)

    # Update in database
    success = await instance_repo.update(instance_id, update_dict)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update instance"
        )

    # If setting as default, unset all others
    if update_dict.get("is_default"):
        await instance_repo.set_as_default(instance_id)

    # Fetch updated instance
    updated_instance = await instance_repo.get_by_id(instance_id)

    logger.info(f"Updated GitLab instance '{updated_instance.name}' by user {current_user.username}")

    return _to_response(updated_instance)


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_instance(
    instance_id: str,
    force: bool = False,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Delete a GitLab instance.
    Requires system:manage permission.

    - Fails if projects are still linked (unless force=true)
    - Use force=true to delete despite dependencies (projects will be orphaned)
    """
    instance_repo = GitLabInstanceRepository(db)
    project_repo = ProjectRepository(db)

    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GitLab instance with ID {instance_id} not found"
        )

    # Check for dependent projects
    project_count = await project_repo.count_by_instance(instance_id)

    if project_count > 0 and not force:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot delete instance '{instance.name}': {project_count} projects "
                f"are still linked. Set gitlab_instance_id=null on projects first "
                f"or use force=true to delete anyway."
            )
        )

    # Delete instance
    success = await instance_repo.delete(instance_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete instance"
        )

    logger.warning(
        f"Deleted GitLab instance '{instance.name}' by user {current_user.username} "
        f"(force={force}, orphaned_projects={project_count})"
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{instance_id}/test-connection", response_model=GitLabInstanceTestConnectionResponse)
async def test_connection(
    instance_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Test connection to a GitLab instance.
    Requires system:manage permission.

    Calls GitLab's /version endpoint to verify connectivity and credentials.
    """
    instance_repo = GitLabInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GitLab instance with ID {instance_id} not found"
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
            response = await client.get(
                f"{gitlab_service.api_url}/version",
                headers=gitlab_service._get_auth_headers()
            )

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
        logger.error(f"Connection test failed for instance '{instance.name}': {e}")
        return GitLabInstanceTestConnectionResponse(
            success=False,
            message=f"Connection failed: {str(e)}",
            gitlab_version=None,
            instance_name=instance.name,
            url=instance.url,
        )
