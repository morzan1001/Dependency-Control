"""
System Helper Functions

Shared utilities for system settings operations.
"""

from typing import List

from app.core.constants import (
    NOTIFICATION_CHANNEL_EMAIL,
    NOTIFICATION_CHANNEL_MATTERMOST,
    NOTIFICATION_CHANNEL_SLACK,
)
from app.models.system import SystemSettings


def get_available_channels(settings: SystemSettings) -> List[str]:
    """
    Determine available notification channels based on system settings.

    Checks the system settings for configured notification providers
    and returns a list of available channel identifiers.

    Args:
        settings: Current system settings containing integration configurations

    Returns:
        List of available notification channel identifiers
        (e.g., ["email", "slack", "mattermost"])
    """
    channels: List[str] = []

    # Email requires SMTP host and user
    if settings.smtp_host and settings.smtp_user:
        channels.append(NOTIFICATION_CHANNEL_EMAIL)

    # Slack requires bot token
    if settings.slack_bot_token:
        channels.append(NOTIFICATION_CHANNEL_SLACK)

    # Mattermost requires both bot token and URL
    if settings.mattermost_bot_token and settings.mattermost_url:
        channels.append(NOTIFICATION_CHANNEL_MATTERMOST)

    return channels
