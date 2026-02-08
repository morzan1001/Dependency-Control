from typing import List

from fastapi import Depends

from app.api.router import CustomAPIRouter
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.v1.helpers import get_available_channels
from app.core.constants import (
    NOTIFICATION_CHANNEL_EMAIL,
    NOTIFICATION_CHANNEL_MATTERMOST,
    NOTIFICATION_CHANNEL_SLACK,
)
from app.db.mongodb import get_database
from app.models.user import User
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.system import (
    AppConfig,
    NotificationChannels,
    PublicConfig,
    SystemSettingsResponse,
    SystemSettingsUpdate,
)

router = CustomAPIRouter()


@router.get("/", response_model=SystemSettingsResponse)
@router.get("/settings", response_model=SystemSettingsResponse)
async def get_settings(
    current_user: User = Depends(deps.PermissionChecker("system:manage")),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get system settings. Requires 'system:manage' permission.
    """
    return await deps.get_system_settings(db, auto_init=True)


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
    repo = SystemSettingsRepository(db)
    update_data = settings_in.model_dump(exclude_unset=True)

    # Check if slack_bot_token is being manually updated
    if "slack_bot_token" in update_data:
        current_settings = await repo.get()
        current_token = current_settings.slack_bot_token
        new_token = update_data.get("slack_bot_token")

        # If the token has changed (and it's not just a re-save of the existing one),
        # we assume it's a manual update and clear the OAuth rotation fields.
        if new_token != current_token:
            update_data["slack_refresh_token"] = None
            update_data["slack_token_expires_at"] = None

    return await repo.update(update_data)


@router.get(
    "/public-config",
    response_model=PublicConfig,
    summary="Get public system configuration",
)
async def get_public_config(db: AsyncIOMotorDatabase = Depends(get_database)):
    """
    Returns public configuration flags (e.g. if registration is allowed).
    No authentication required.
    """
    settings = await deps.get_system_settings(db)
    return PublicConfig(
        allow_public_registration=settings.allow_public_registration,
        enforce_2fa=settings.enforce_2fa,
        enforce_email_verification=settings.enforce_email_verification,
        oidc_enabled=settings.oidc_enabled,
        oidc_provider_name=settings.oidc_provider_name,
    )


@router.get(
    "/app-config",
    response_model=AppConfig,
    summary="Get application configuration for authenticated users",
)
async def get_app_config(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Returns lightweight, non-sensitive configuration for authenticated users.
    This endpoint provides only the data needed by frontend components
    without exposing secrets like API keys or passwords.
    """
    settings = await deps.get_system_settings(db)

    # Determine available notification channels using helper
    channels = get_available_channels(settings)
    notifications = NotificationChannels(
        email=NOTIFICATION_CHANNEL_EMAIL in channels,
        slack=NOTIFICATION_CHANNEL_SLACK in channels,
        mattermost=NOTIFICATION_CHANNEL_MATTERMOST in channels,
    )

    return AppConfig(
        project_limit_per_user=settings.project_limit_per_user,
        retention_mode=settings.retention_mode,
        global_retention_days=settings.global_retention_days,
        rescan_mode=settings.rescan_mode,
        global_rescan_enabled=settings.global_rescan_enabled,
        global_rescan_interval=settings.global_rescan_interval,
        notifications=notifications,
    )


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
    settings = await deps.get_system_settings(db)
    return get_available_channels(settings)
