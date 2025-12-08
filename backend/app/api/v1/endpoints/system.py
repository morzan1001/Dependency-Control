from fastapi import APIRouter, Depends, HTTPException, Body
from typing import List, Dict
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.config import settings
from app.db.mongodb import get_database
from app.models.user import User
from app.api import deps

router = APIRouter()

@router.get("/signup-status", response_model=Dict[str, bool], summary="Check if signup is enabled")
async def get_signup_status(
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Returns the current status of user signup.
    """
    config = await db.system_settings.find_one({"_id": "signup_config"})
    enabled = config.get("enabled", True) if config else True
    return {"enabled": enabled}

@router.put("/signup-status", response_model=Dict[str, bool], summary="Enable or disable signup")
async def set_signup_status(
    enabled: bool = Body(..., embed=True),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Enable or disable user signup. Requires admin permissions.
    """
    if "*" not in current_user.permissions and "system:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    await db.system_settings.update_one(
        {"_id": "signup_config"},
        {"$set": {"enabled": enabled}},
        upsert=True
    )
    return {"enabled": enabled}

@router.get("/notifications/channels", response_model=List[str], summary="Get available notification channels")
async def get_notification_channels():
    """
    Returns a list of available notification channels based on the server configuration.
    """
    channels = []
    
    # Check Email
    if settings.SMTP_HOST and settings.SMTP_USER:
        channels.append("email")
        
    # Check Slack
    if settings.SLACK_BOT_TOKEN:
        channels.append("slack")
        
    # Check Mattermost
    if settings.MATTERMOST_BOT_TOKEN and settings.MATTERMOST_URL:
        channels.append("mattermost")
        
    return channels
