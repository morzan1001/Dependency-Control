"""Shared utilities for system settings operations."""

from typing import List

from app.core.constants import (
    NOTIFICATION_CHANNEL_EMAIL,
    NOTIFICATION_CHANNEL_MATTERMOST,
    NOTIFICATION_CHANNEL_SLACK,
)
from app.models.system import SystemSettings


def get_available_channels(settings: SystemSettings) -> List[str]:
    """Return the notification channels configured in system settings."""
    channels: List[str] = []

    if settings.smtp_host and settings.smtp_user:
        channels.append(NOTIFICATION_CHANNEL_EMAIL)

    if settings.slack_bot_token:
        channels.append(NOTIFICATION_CHANNEL_SLACK)

    if settings.mattermost_bot_token and settings.mattermost_url:
        channels.append(NOTIFICATION_CHANNEL_MATTERMOST)

    return channels
