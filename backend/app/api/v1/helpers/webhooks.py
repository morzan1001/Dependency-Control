"""Shared helper functions for webhook-related operations."""

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.teams import check_team_access, get_team_with_access
from app.core.constants import PROJECT_ROLE_ADMIN, TEAM_ROLE_ADMIN, TEAM_ROLE_MEMBER
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.models.webhook import Webhook
from app.repositories.webhooks import WebhookRepository


async def get_webhook_or_404(
    webhook_repo: WebhookRepository,
    webhook_id: str,
) -> Webhook:
    """Fetch a webhook by ID, raising 404 if not found."""
    webhook = await webhook_repo.get_by_id(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return webhook


async def check_webhook_permission(
    current_user: User,
    db: AsyncIOMotorDatabase,
    required_permission: str,
    *,
    project_id: str | None = None,
    team_id: str | None = None,
) -> None:
    """The permission plus scope access (writes need membership or the write grant, never read_all), else scope admin.

    Global webhooks require system:manage.
    """
    has_perm = has_permission(current_user.permissions, required_permission)
    if project_id:
        if not has_perm:
            await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
        elif required_permission == Permissions.WEBHOOK_READ:
            await check_project_access(project_id, current_user, db)
        else:
            await check_project_access(project_id, current_user, db, write=True)
    elif team_id:
        if not has_perm:
            await check_team_access(team_id, current_user, db, required_role=TEAM_ROLE_ADMIN)
        elif required_permission == Permissions.WEBHOOK_READ:
            await check_team_access(team_id, current_user, db)
        else:
            await get_team_with_access(team_id, current_user, db, required_role=TEAM_ROLE_MEMBER)
    elif not has_permission(current_user.permissions, Permissions.SYSTEM_MANAGE):
        raise HTTPException(status_code=403, detail="Not enough permissions")
