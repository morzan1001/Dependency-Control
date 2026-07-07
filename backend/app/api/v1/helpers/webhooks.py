"""Shared helper functions for webhook-related operations."""

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.teams import check_team_access
from app.core.constants import PROJECT_ROLE_ADMIN, TEAM_ROLE_ADMIN
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.models.webhook import Webhook
from app.repositories import WebhookRepository


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
    webhook: Webhook,
    current_user: User,
    db: AsyncIOMotorDatabase,
    required_permission: str,
) -> None:
    """Authorize access to a webhook: the specific permission plus resource access, or admin role.

    Global (unscoped) webhooks require system:manage. Raises 403 on failure.
    """
    if webhook.project_id:
        has_perm = has_permission(current_user.permissions, required_permission)
        if has_perm:
            await check_project_access(webhook.project_id, current_user, db)
        else:
            await check_project_access(webhook.project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)
    elif webhook.team_id:
        has_perm = has_permission(current_user.permissions, required_permission)
        if has_perm:
            await check_team_access(webhook.team_id, current_user, db)
        else:
            await check_team_access(webhook.team_id, current_user, db, required_role=TEAM_ROLE_ADMIN)
    else:
        if not has_permission(current_user.permissions, Permissions.SYSTEM_MANAGE):
            raise HTTPException(status_code=403, detail="Not enough permissions")


async def check_webhook_list_permission(
    project_id: str,
    current_user: User,
    db: AsyncIOMotorDatabase,
) -> None:
    """Authorize listing a project's webhooks: webhook:read plus access, or project admin."""
    has_read_perm = has_permission(current_user.permissions, Permissions.WEBHOOK_READ)
    if has_read_perm:
        await check_project_access(project_id, current_user, db)
    else:
        await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)


async def check_webhook_create_permission(
    project_id: str,
    current_user: User,
    db: AsyncIOMotorDatabase,
) -> None:
    """Authorize creating a project's webhooks: webhook:create plus access, or project admin."""
    has_create_perm = has_permission(current_user.permissions, Permissions.WEBHOOK_CREATE)
    if has_create_perm:
        await check_project_access(project_id, current_user, db)
    else:
        await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN)


async def check_team_webhook_list_permission(
    team_id: str,
    current_user: User,
    db: AsyncIOMotorDatabase,
) -> None:
    """Authorize listing a team's webhooks: webhook:read plus membership, or team admin."""
    has_read_perm = has_permission(current_user.permissions, Permissions.WEBHOOK_READ)
    if has_read_perm:
        await check_team_access(team_id, current_user, db)
    else:
        await check_team_access(team_id, current_user, db, required_role=TEAM_ROLE_ADMIN)


async def check_team_webhook_create_permission(
    team_id: str,
    current_user: User,
    db: AsyncIOMotorDatabase,
) -> None:
    """Authorize creating a team's webhooks: webhook:create plus membership, or team admin."""
    has_create_perm = has_permission(current_user.permissions, Permissions.WEBHOOK_CREATE)
    if has_create_perm:
        await check_team_access(team_id, current_user, db)
    else:
        await check_team_access(team_id, current_user, db, required_role=TEAM_ROLE_ADMIN)
