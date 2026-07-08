import logging
from datetime import datetime, timezone
from typing import Annotated, Any, Dict

from fastapi import Depends, HTTPException, status
from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import build_pagination_response
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
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400, RESP_AUTH_400_404_500, RESP_AUTH_404
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
) -> Dict[str, Any]:
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
            detail=f"Failed to reach OIDC endpoint: {str(e)}",
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

    if "name" in update_dict and update_dict["name"] != instance.name:
        if await instance_repo.exists_by_name(update_dict["name"], exclude_id=instance_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another instance with name '{update_dict['name']}' already exists",
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


@router.post("/{instance_id}/test-connection", responses=RESP_AUTH_404)
async def test_connection(
    instance_id: str,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE))],
) -> GitHubInstanceTestConnectionResponse:
    """Test OIDC connectivity by fetching the JWKS from the configured issuer URL."""
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
        logger.exception("Connection test failed for GitHub instance '%s': %s", instance.name, e)
        return GitHubInstanceTestConnectionResponse(
            success=False,
            message=f"Connection failed: {str(e)}",
            instance_name=instance.name,
            url=instance.url,
        )
