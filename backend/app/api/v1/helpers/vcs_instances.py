import logging
import math
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any

from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel

from app.api.v1.helpers.pagination import build_pagination_response
from app.core.constants import team_source
from app.models.base import VcsInstanceModel
from app.models.github_instance import GitHubInstance
from app.models.gitlab_instance import GitLabInstance
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository
from app.repositories.vcs_instances import VcsInstanceRepository
from app.services.github import GitHubService

logger = logging.getLogger(__name__)


async def get_or_404[T: VcsInstanceModel](repo: VcsInstanceRepository[T], instance_id: str, label: str) -> T:
    instance = await repo.get_by_id(instance_id)
    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{label} instance with ID {instance_id} not found"
        )
    return instance


async def list_page[T: VcsInstanceModel](
    repo: VcsInstanceRepository[T], page: int, size: int, active_only: bool, to_response: Callable[[T], BaseModel]
) -> dict[str, Any]:
    skip = (page - 1) * size
    query: dict[str, Any] = {"is_active": True} if active_only else {}
    instances = await repo.find_many(query, skip=skip, limit=size)
    return build_pagination_response(
        [to_response(instance) for instance in instances], await repo.count(query), skip, size
    )


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


async def apply_update[T: GitLabInstance | GitHubInstance](
    repo: VcsInstanceRepository[T],
    instance_id: str,
    update_data: BaseModel,
    label: str,
    username: str,
    allowlist_refusal: str,
) -> T:
    instance = await get_or_404(repo, instance_id, label)
    update_dict = update_data.model_dump(exclude_unset=True)

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
    if instance.model_copy(update=update_dict).lacks_required_allowlist():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=allowlist_refusal)

    update_dict["last_modified_at"] = datetime.now(timezone.utc)
    updated = await repo.update(instance_id, update_dict)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found after update")
    logger.info("Updated %s instance '%s' by user %s", label, updated.name, username)
    return updated


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


class Refusal(Enum):
    BUDGET = auto()
    SCOPE = auto()
    UNDETERMINED = auto()


async def why_refused(github_service: GitHubService) -> tuple[Refusal, str]:
    """Asks the uncharged GET /rate_limit only when the read's own rate-limit headers are silent."""
    reset_at = github_service.rate_limited_until
    if reset_at is None:
        limit = await github_service.get_core_rate_limit()
        if limit is None:
            return Refusal.UNDETERMINED, ""
        if limit.remaining > 0:
            return Refusal.SCOPE, ""
        reset_at = limit.reset_at
    minutes = math.ceil((reset_at - datetime.now(timezone.utc)).total_seconds() / 60)
    due = f"about {minutes} minute(s) from now" if minutes > 0 else "any moment now"
    return Refusal.BUDGET, f"{reset_at:%Y-%m-%d %H:%M UTC}, {due}"


async def refused_listing(github_service: GitHubService, subject: str, scope_hint: str) -> HTTPException:
    """Names what refused rather than assuming a missing scope."""
    cause, reset = await why_refused(github_service)
    if cause is Refusal.BUDGET:
        detail = (
            f"Could not list {subject}: the token's GitHub API rate limit is exhausted. The limit resets at {reset}."
        )
    elif cause is Refusal.SCOPE:
        detail = f"Could not list {subject}. {scope_hint}"
    else:
        detail = (
            f"Could not list {subject}, and GET /rate_limit did not answer either, so whether an "
            "exhausted rate limit or a missing read:org refused could not be determined. Check both."
        )
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)
