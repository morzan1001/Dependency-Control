from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.db.mongodb import get_database
from app.models.system import SystemSettings
from app.models.user import User
from app.schemas.system import SystemSettingsResponse, SystemSettingsUpdate

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
@router.get("/settings", response_model=SystemSettingsResponse)
async def get_settings(
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get system settings. Requires 'system:manage' permission.
    """
    return await get_current_settings(db)


@router.put("/", response_model=SystemSettingsResponse)
@router.put("/settings", response_model=SystemSettingsResponse)
async def update_settings(
    settings_in: SystemSettingsUpdate,
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update system settings. Requires 'system:manage' permission.
    """
    update_data = settings_in.dict(exclude_unset=True)

    # Check if slack_bot_token is being manually updated
    if "slack_bot_token" in update_data:
        current_settings = await db.system_settings.find_one({"_id": "current"})
        if current_settings:
            current_token = current_settings.get("slack_bot_token")
            new_token = update_data.get("slack_bot_token")

            # If the token has changed (and it's not just a re-save of the existing one),
            # we assume it's a manual update and clear the OAuth rotation fields.
            if new_token != current_token:
                update_data["slack_refresh_token"] = None
                update_data["slack_token_expires_at"] = None

    await db.system_settings.update_one(
        {"_id": "current"}, {"$set": update_data}, upsert=True
    )

    return await get_current_settings(db)


@router.get(
    "/public-config",
    response_model=Dict[str, Any],
    summary="Get public system configuration",
)
async def get_public_config(db: AsyncIOMotorDatabase = Depends(get_database)):
    """
    Returns public configuration flags (e.g. if registration is allowed).
    """
    settings = await get_current_settings(db)
    return {
        "allow_public_registration": settings.allow_public_registration,
        "enforce_2fa": settings.enforce_2fa,
        "enforce_email_verification": settings.enforce_email_verification,
        "oidc_enabled": settings.oidc_enabled,
        "oidc_provider_name": settings.oidc_provider_name,
    }


@router.get(
    "/notifications/channels",
    response_model=List[str],
    summary="Get available notification channels",
)
async def get_notification_channels(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Returns a list of available notification channels based on the server configuration.
    Requires authentication.
    """
    settings = await get_current_settings(db)
    channels = []

    # Check Email
    if settings.smtp_host and settings.smtp_user:
        channels.append("email")

    # Check Slack
    if settings.slack_bot_token:
        channels.append("slack")

    # Check Mattermost
    if settings.mattermost_bot_token and settings.mattermost_url:
        channels.append("mattermost")

    return channels
