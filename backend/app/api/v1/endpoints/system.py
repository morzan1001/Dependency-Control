from fastapi import APIRouter, Depends, HTTPException, Body
from typing import List, Dict
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.config import settings as env_settings
from app.db.mongodb import get_database
from app.models.user import User
from app.models.system import SystemSettings
from app.schemas.system import SystemSettingsResponse, SystemSettingsUpdate
from app.api import deps

router = APIRouter()

async def get_current_settings(db: AsyncIOMotorDatabase) -> SystemSettings:
    data = await db.system_settings.find_one({"_id": "current"})
    if not data:
        # Initialize with defaults if not found
        settings_model = SystemSettings()
        await db.system_settings.insert_one(settings_model.dict(by_alias=True))
        return settings_model
    return SystemSettings(**data)

@router.get("/", response_model=SystemSettingsResponse)
async def get_settings(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Get system settings. Requires 'system:manage' permission.
    """
    if "*" not in current_user.permissions and "system:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return await get_current_settings(db)

@router.put("/", response_model=SystemSettingsResponse)
async def update_settings(
    settings_in: SystemSettingsUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update system settings. Requires 'system:manage' permission.
    """
    if "*" not in current_user.permissions and "system:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    update_data = settings_in.dict(exclude_unset=True)
    
    await db.system_settings.update_one(
        {"_id": "current"},
        {"$set": update_data},
        upsert=True
    )
    
    return await get_current_settings(db)

@router.get("/public-config", response_model=Dict[str, bool], summary="Get public system configuration")
async def get_public_config(
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Returns public configuration flags (e.g. if registration is allowed).
    """
    settings = await get_current_settings(db)
    return {
        "allow_public_registration": settings.allow_public_registration,
        "enforce_2fa": settings.enforce_2fa
    }

@router.get("/notifications/channels", response_model=List[str], summary="Get available notification channels")
async def get_notification_channels(
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Returns a list of available notification channels based on the server configuration.
    """
    settings = await get_current_settings(db)
    channels = []
    
    # Check Email
    if settings.smtp_host and settings.smtp_user:
        channels.append("email")
    # Fallback to env vars if not in DB (migration path)
    elif env_settings.SMTP_HOST and env_settings.SMTP_USER:
        channels.append("email")
        
    # Check Slack
    if settings.slack_bot_token or env_settings.SLACK_BOT_TOKEN:
        channels.append("slack")
        
    # Check Mattermost
    if (settings.mattermost_bot_token and settings.mattermost_url) or \
       (env_settings.MATTERMOST_BOT_TOKEN and env_settings.MATTERMOST_URL):
        channels.append("mattermost")
        
    return channels
