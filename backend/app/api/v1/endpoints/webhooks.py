from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.models.user import User
from app.models.webhook import Webhook
from app.schemas.webhook import WebhookCreate, WebhookResponse, WebhookUpdate
from app.db.mongodb import get_database
from app.api.v1.endpoints.projects import check_project_access

router = APIRouter()

@router.post("/project/{project_id}", response_model=WebhookResponse, status_code=201)
async def create_webhook(
    project_id: str,
    webhook_in: WebhookCreate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Create a webhook for a project.
    """
    if "*" not in current_user.permissions and "webhook:create" not in current_user.permissions:
        await check_project_access(project_id, current_user, db, required_role="admin")
    
    webhook = Webhook(
        project_id=project_id,
        **webhook_in.dict()
    )
    
    await db.webhooks.insert_one(webhook.dict(by_alias=True))
    return webhook

@router.get("/project/{project_id}", response_model=List[WebhookResponse])
async def list_webhooks(
    project_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    await check_project_access(project_id, current_user, db, required_role="admin")
    
    webhooks = await db.webhooks.find({"project_id": project_id}).to_list(100)
    return [Webhook(**w) for w in webhooks]

@router.post("/global/", response_model=WebhookResponse, status_code=201)
async def create_global_webhook(
    webhook_in: WebhookCreate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Create a global webhook. Requires 'system:manage' permission.
    """
    if "*" not in current_user.permissions and "system:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    webhook = Webhook(
        project_id=None,
        **webhook_in.dict()
    )
    
    await db.webhooks.insert_one(webhook.dict(by_alias=True))
    return webhook

@router.get("/global/", response_model=List[WebhookResponse])
async def list_global_webhooks(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    List global webhooks. Requires 'system:manage' permission.
    """
    if "*" not in current_user.permissions and "system:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    webhooks = await db.webhooks.find({"project_id": None}).to_list(100)
    return [Webhook(**w) for w in webhooks]

@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    webhook_data = await db.webhooks.find_one({"_id": webhook_id})
    if not webhook_data:
        raise HTTPException(status_code=404, detail="Webhook not found")
        
    webhook = Webhook(**webhook_data)
    
    if webhook.project_id:
        if "*" not in current_user.permissions and "webhook:delete" not in current_user.permissions:
            await check_project_access(webhook.project_id, current_user, db, required_role="admin")
    else:
        # Global webhook
        if "*" not in current_user.permissions and "system:manage" not in current_user.permissions:
            raise HTTPException(status_code=403, detail="Not enough permissions")
    
    await db.webhooks.delete_one({"_id": webhook_id})
