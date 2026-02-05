"""
Webhook API endpoints for managing webhook configurations.

Provides CRUD operations for project-specific and global webhooks,
plus webhook testing functionality.
"""

from typing import Any, Dict

from fastapi import Depends, HTTPException, Query

from app.api.router import CustomAPIRouter
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.v1.helpers import (
    build_pagination_response,
    check_webhook_create_permission,
    check_webhook_list_permission,
    check_webhook_permission,
    get_webhook_or_404,
)
from app.core.permissions import Permissions
from app.db.mongodb import get_database
from app.models.user import User
from app.models.webhook import Webhook
from app.repositories import WebhookRepository
from app.schemas.webhook import (
    WebhookCreate,
    WebhookResponse,
    WebhookTestRequest,
    WebhookTestResponse,
    WebhookUpdate,
)
from app.services.webhooks.webhook_service import webhook_service

router = CustomAPIRouter()


@router.post("/project/{project_id}", response_model=WebhookResponse, status_code=201)
async def create_webhook(
    project_id: str,
    webhook_in: WebhookCreate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a webhook for a project.

    Requires 'webhook:create' permission with project access, or project admin role.
    """
    await check_webhook_create_permission(project_id, current_user, db)

    webhook_repo = WebhookRepository(db)
    webhook = Webhook(project_id=project_id, **webhook_in.model_dump())

    return await webhook_repo.create(webhook)


@router.get("/project/{project_id}", response_model=Dict[str, Any])
async def list_webhooks(
    project_id: str,
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of items to return"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List all webhooks for a project with pagination.

    Requires 'webhook:read' permission with project access, or project admin role.
    """
    await check_webhook_list_permission(project_id, current_user, db)

    webhook_repo = WebhookRepository(db)
    total = await webhook_repo.count_by_project(project_id)
    webhooks = await webhook_repo.find_by_project(project_id, skip=skip, limit=limit)

    items = [w.model_dump() for w in webhooks]
    return build_pagination_response(items, total, skip, limit)


@router.post("/global/", response_model=WebhookResponse, status_code=201)
async def create_global_webhook(
    webhook_in: WebhookCreate,
    current_user: User = Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE)),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a global webhook.

    Global webhooks are triggered for all projects.
    Requires 'system:manage' permission.
    """
    webhook_repo = WebhookRepository(db)
    webhook = Webhook(project_id=None, **webhook_in.model_dump())

    return await webhook_repo.create(webhook)


@router.get("/global/", response_model=Dict[str, Any])
async def list_global_webhooks(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of items to return"),
    current_user: User = Depends(deps.PermissionChecker(Permissions.SYSTEM_MANAGE)),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List global webhooks with pagination.

    Requires 'system:manage' permission.
    """
    webhook_repo = WebhookRepository(db)
    total = await webhook_repo.count_global()
    webhooks = await webhook_repo.find_global(skip=skip, limit=limit)

    items = [w.model_dump() for w in webhooks]
    return build_pagination_response(items, total, skip, limit)


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a specific webhook by ID.

    Requires 'webhook:read' permission with project access, or project admin role.
    For global webhooks: requires 'system:manage' permission.
    """
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(webhook, current_user, db, Permissions.WEBHOOK_READ)
    return webhook


@router.patch("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    webhook_update: WebhookUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update a webhook configuration.

    Only provided fields will be updated.
    Requires 'webhook:update' permission with project access, or project admin role.
    For global webhooks: requires 'system:manage' permission.
    """
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(
        webhook, current_user, db, Permissions.WEBHOOK_UPDATE
    )

    # Build update dict with only provided fields
    update_data = webhook_update.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Update and return updated webhook
    updated_webhook = await webhook_repo.update(webhook_id, update_data)
    return updated_webhook


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> None:
    """
    Delete a webhook.

    Requires 'webhook:delete' permission with project access, or project admin role.
    For global webhooks: requires 'system:manage' permission.
    """
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(
        webhook, current_user, db, Permissions.WEBHOOK_DELETE
    )

    await webhook_repo.delete(webhook_id)


@router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
async def test_webhook(
    webhook_id: str,
    test_request: WebhookTestRequest = WebhookTestRequest(),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Send a test webhook to verify the configuration.

    Sends a test payload to the webhook URL and returns the result.
    Useful for verifying webhook configuration before relying on it.
    Requires 'webhook:update' permission with project access, or project admin role.
    For global webhooks: requires 'system:manage' permission.
    """
    webhook_repo = WebhookRepository(db)
    webhook = await get_webhook_or_404(webhook_repo, webhook_id)
    await check_webhook_permission(
        webhook, current_user, db, Permissions.WEBHOOK_UPDATE
    )

    # Send test webhook
    result = await webhook_service.test_webhook(webhook, test_request.event_type)

    return WebhookTestResponse(**result)
