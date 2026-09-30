"""The provider-neutral half of the GitLab and GitHub instance endpoints."""

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import team_source
from app.models.base import VcsInstanceModel
from app.models.github_instance import GitHubInstance
from app.models.gitlab_instance import GitLabInstance
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository
from app.repositories.vcs_instances import VcsInstanceRepository

logger = logging.getLogger(__name__)


async def get_or_404[T: VcsInstanceModel](repo: VcsInstanceRepository[T], instance_id: str, label: str) -> T:
    instance = await repo.get_by_id(instance_id)
    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{label} instance with ID {instance_id} not found"
        )
    return instance


async def list_page[T: VcsInstanceModel](
    repo: VcsInstanceRepository[T], page: int, size: int, active_only: bool
) -> tuple[list[T], int, int]:
    """One page of instances, how many there are, and the page's offset."""
    skip = (page - 1) * size
    query: dict[str, Any] = {"is_active": True} if active_only else {}
    return await repo.find_many(query, skip=skip, limit=size), await repo.count(query), skip


async def assert_unique(
    repo: VcsInstanceRepository[Any],
    label: str,
    *,
    url: str | None = None,
    name: str | None = None,
    exclude_id: str | None = None,
) -> None:
    subject = "Another instance" if exclude_id else f"A {label} instance"
    if url is not None and await repo.exists_by_url(url, exclude_id=exclude_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"{subject} with URL '{url}' already exists"
        )
    if name is not None and await repo.exists_by_name(name, exclude_id=exclude_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"{subject} with name '{name}' already exists"
        )


async def prepare_update(
    repo: VcsInstanceRepository[Any], instance: GitLabInstance | GitHubInstance, update_dict: dict[str, Any]
) -> None:
    """Refuse a URL or name another instance holds and team sync without a token, then stamp the change."""

    def changed(field: str) -> Any:
        value = update_dict.get(field)
        return value if field in update_dict and value != getattr(instance, field) else None

    await assert_unique(repo, "", url=changed("url"), name=changed("name"), exclude_id=str(instance.id))
    if update_dict.get("sync_teams", instance.sync_teams) and not update_dict.get(
        "access_token", instance.access_token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="An access token is required to enable team syncing"
        )
    update_dict["last_modified_at"] = datetime.now(timezone.utc)


async def delete_guarded(
    db: AsyncIOMotorDatabase[Any],
    repo: VcsInstanceRepository[Any],
    instance: GitLabInstance | GitHubInstance,
    *,
    provider: str,
    username: str,
) -> None:
    instance_id = str(instance.id)
    project_count = await ProjectRepository(db).count({repo.project_link_field: instance_id})
    if project_count:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot delete instance '{instance.name}': {project_count} projects are still linked. "
                "Delete those projects first, or edit this instance in place instead of re-creating it."
            ),
        )
    # Teams first: a failure then leaves the instance in place, so the delete can be retried.
    detached = await TeamRepository(db).remove_instance(instance_id, team_source(provider, instance_id))
    if not await repo.delete(instance_id):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete instance")
    logger.warning(
        "Deleted %s instance '%s' by user %s, detached from %d teams", provider, instance.name, username, detached
    )
