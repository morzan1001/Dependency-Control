import logging
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Response, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import build_pagination_response
from app.db.mongodb import get_database
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
    """Convert GitHubInstance to response schema."""
    return GitHubInstanceResponse(
        id=str(instance.id),
        name=instance.name,
        url=instance.url,
        github_url=instance.github_url,
        description=instance.description,
        is_active=instance.is_active,
        oidc_audience=instance.oidc_audience,
        auto_create_projects=instance.auto_create_projects,
        created_at=instance.created_at,
        created_by=instance.created_by,
        last_modified_at=instance.last_modified_at,
    )


@router.get("/", response_model=GitHubInstanceList)
async def list_instances(
    page: int = 1,
    size: int = 100,
    active_only: bool = False,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    List all GitHub instances.
    Requires system:manage permission.
    """
    instance_repo = GitHubInstanceRepository(db)

    skip = (page - 1) * size

    if active_only:
        instances = await instance_repo.list_active(skip=skip, limit=size)
        total = await instance_repo.count_active()
    else:
        instances = await instance_repo.list_all(skip=skip, limit=size)
        total = await instance_repo.count_all()

    items = [_to_response(instance) for instance in instances]

    return build_pagination_response(items, total, page, size)


@router.get("/{instance_id}", response_model=GitHubInstanceResponse)
async def get_instance(
    instance_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Get a specific GitHub instance by ID.
    Requires system:manage permission.
    """
    instance_repo = GitHubInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    return _to_response(instance)


@router.post("/", response_model=GitHubInstanceResponse, status_code=status.HTTP_201_CREATED)
async def create_instance(
    instance_data: GitHubInstanceCreate,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Create a new GitHub instance.
    Requires system:manage permission.

    - Validates that URL and name are unique
    - Tests JWKS endpoint reachability before creating
    """
    instance_repo = GitHubInstanceRepository(db)

    # Validate URL uniqueness
    if await instance_repo.exists_by_url(instance_data.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitHub instance with URL '{instance_data.url}' already exists",
        )

    # Validate name uniqueness
    if await instance_repo.exists_by_name(instance_data.name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A GitHub instance with name '{instance_data.name}' already exists",
        )

    # Create instance object
    new_instance = GitHubInstance(
        name=instance_data.name,
        url=instance_data.url.rstrip("/"),
        github_url=instance_data.github_url,
        description=instance_data.description,
        is_active=instance_data.is_active,
        oidc_audience=instance_data.oidc_audience,
        auto_create_projects=instance_data.auto_create_projects,
        created_by=str(current_user.id),
        created_at=datetime.now(timezone.utc),
    )

    # Test JWKS endpoint reachability before saving
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
        logger.error(f"JWKS connectivity test failed for {instance_data.url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to reach OIDC endpoint: {str(e)}",
        )

    # Save to database
    created_instance = await instance_repo.create(new_instance)

    logger.info(f"Created GitHub instance '{created_instance.name}' by user {current_user.username}")

    return _to_response(created_instance)


@router.put("/{instance_id}", response_model=GitHubInstanceResponse)
async def update_instance(
    instance_id: str,
    update_data: GitHubInstanceUpdate,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Update a GitHub instance.
    Requires system:manage permission.

    - Only updates provided fields
    - Validates uniqueness constraints
    """
    instance_repo = GitHubInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    # Build update dict (only non-None values)
    update_dict = update_data.model_dump(exclude_unset=True)

    # Validate URL uniqueness if changing URL
    if "url" in update_dict and update_dict["url"] != instance.url:
        if await instance_repo.exists_by_url(update_dict["url"], exclude_id=instance_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another instance with URL '{update_dict['url']}' already exists",
            )
        # Normalize URL
        update_dict["url"] = update_dict["url"].rstrip("/")

    # Validate name uniqueness if changing name
    if "name" in update_dict and update_dict["name"] != instance.name:
        if await instance_repo.exists_by_name(update_dict["name"], exclude_id=instance_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another instance with name '{update_dict['name']}' already exists",
            )

    # Add last_modified metadata
    update_dict["last_modified_at"] = datetime.now(timezone.utc)

    # Update in database
    success = await instance_repo.update(instance_id, update_dict)

    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update instance")

    # Fetch updated instance
    updated_instance = await instance_repo.get_by_id(instance_id)

    logger.info(f"Updated GitHub instance '{updated_instance.name}' by user {current_user.username}")

    return _to_response(updated_instance)


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_instance(
    instance_id: str,
    force: bool = False,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Delete a GitHub instance.
    Requires system:manage permission.

    - Fails if projects are still linked (unless force=true)
    - Use force=true to delete despite dependencies (projects will be orphaned)
    """
    instance_repo = GitHubInstanceRepository(db)
    project_repo = ProjectRepository(db)

    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    # Check for dependent projects
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

    # Delete instance
    success = await instance_repo.delete(instance_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete instance")

    logger.warning(
        f"Deleted GitHub instance '{instance.name}' by user {current_user.username} "
        f"(force={force}, orphaned_projects={project_count})"
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{instance_id}/test-connection", response_model=GitHubInstanceTestConnectionResponse)
async def test_connection(
    instance_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
):
    """
    Test OIDC endpoint connectivity for a GitHub instance.
    Requires system:manage permission.

    Fetches the JWKS from the configured issuer URL to verify reachability.
    """
    instance_repo = GitHubInstanceRepository(db)
    instance = await instance_repo.get_by_id(instance_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"GitHub instance with ID {instance_id} not found"
        )

    github_service = GitHubService(instance)

    try:
        jwks = await github_service.get_jwks()

        if jwks and jwks.get("keys"):
            key_count = len(jwks["keys"])
            return GitHubInstanceTestConnectionResponse(
                success=True,
                message=f"OIDC endpoint reachable. Found {key_count} signing key(s).",
                instance_name=instance.name,
                url=instance.url,
            )
        else:
            return GitHubInstanceTestConnectionResponse(
                success=False,
                message="JWKS endpoint returned no signing keys",
                instance_name=instance.name,
                url=instance.url,
            )
    except Exception as e:
        logger.error(f"Connection test failed for GitHub instance '{instance.name}': {e}")
        return GitHubInstanceTestConnectionResponse(
            success=False,
            message=f"Connection failed: {str(e)}",
            instance_name=instance.name,
            url=instance.url,
        )
