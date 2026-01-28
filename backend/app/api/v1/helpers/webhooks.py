"""
Webhook Helper Functions

Shared helper functions for webhook-related operations.
"""

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import check_project_access
from app.core.constants import PROJECT_ROLE_ADMIN
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.models.webhook import Webhook
from app.repositories import WebhookRepository


async def get_webhook_or_404(
    webhook_repo: WebhookRepository,
    webhook_id: str,
) -> Webhook:
    """
    Fetch a webhook by ID or raise 404 if not found.

    Args:
        webhook_repo: WebhookRepository instance
        webhook_id: Webhook ID to fetch

    Returns:
        Webhook model instance

    Raises:
        HTTPException: 404 if webhook not found
    """
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
    """
    Check if user has permission to access/modify a webhook.

    For project webhooks: checks specific permission AND project admin role.
    For global webhooks: requires system:manage permission.

    Args:
        webhook: The webhook to check access for
        current_user: Current authenticated user
        db: Database connection
        required_permission: The specific permission to check (e.g., webhook:update)

    Raises:
        HTTPException: 403 if user lacks permissions
    """
    if webhook.project_id:
        # Project webhook: user needs either:
        # 1. The specific permission (e.g., webhook:read) AND project access, OR
        # 2. Project admin role
        has_perm = has_permission(current_user.permissions, required_permission)
        if has_perm:
            # Still need to verify project access (at least viewer level)
            await check_project_access(webhook.project_id, current_user, db)
        else:
            # Fall back to requiring project admin role
            await check_project_access(
                webhook.project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN
            )
    else:
        # Global webhook: requires system:manage
        if not has_permission(current_user.permissions, Permissions.SYSTEM_MANAGE):
            raise HTTPException(status_code=403, detail="Not enough permissions")


async def check_webhook_list_permission(
    project_id: str,
    current_user: User,
    db: AsyncIOMotorDatabase,
) -> None:
    """
    Check if user has permission to list webhooks for a project.

    Users need either:
    - webhook:read permission AND project access, OR
    - Project admin role

    Args:
        project_id: The project ID to check access for
        current_user: Current authenticated user
        db: Database connection

    Raises:
        HTTPException: 403 if user lacks permissions
    """
    has_read_perm = has_permission(current_user.permissions, Permissions.WEBHOOK_READ)
    if has_read_perm:
        # User has webhook:read, but still needs project access
        await check_project_access(project_id, current_user, db)
    else:
        # No webhook:read permission, must be project admin
        await check_project_access(
            project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN
        )


async def check_webhook_create_permission(
    project_id: str,
    current_user: User,
    db: AsyncIOMotorDatabase,
) -> None:
    """
    Check if user has permission to create webhooks for a project.

    Users need either:
    - webhook:create permission AND project access, OR
    - Project admin role

    Args:
        project_id: The project ID to check access for
        current_user: Current authenticated user
        db: Database connection

    Raises:
        HTTPException: 403 if user lacks permissions
    """
    has_create_perm = has_permission(
        current_user.permissions, Permissions.WEBHOOK_CREATE
    )
    if has_create_perm:
        # User has webhook:create, but still needs project access
        await check_project_access(project_id, current_user, db)
    else:
        # No webhook:create permission, must be project admin
        await check_project_access(
            project_id, current_user, db, required_role=PROJECT_ROLE_ADMIN
        )
