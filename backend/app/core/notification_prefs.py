"""Validation helper for per-user notification preferences.

Both the User model and the ProjectNotificationSettings schema accept the same
{event_type: [channels]} structure, so validation is shared here. Unknown
events or channels are dropped with a warning rather than raising — this keeps
old persisted data readable after we add or remove valid events.
"""

import logging
from typing import Annotated, Any

from pydantic import AfterValidator

from app.core.constants import NOTIFICATION_CHANNELS, NOTIFICATION_EVENTS

logger = logging.getLogger(__name__)

_VALID_CHANNELS = set(NOTIFICATION_CHANNELS)


def sanitize_notification_preferences(value: Any) -> dict[str, list[str]]:
    """Drop unknown events/channels, return a normalized dict."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        logger.warning("Invalid notification_preferences type: %s. Using empty dict.", type(value))
        return {}

    cleaned: dict[str, list[str]] = {}
    for event, channels in value.items():
        if event not in NOTIFICATION_EVENTS:
            logger.warning("Unknown notification event '%s' (valid: %s). Dropping.", event, NOTIFICATION_EVENTS)
            continue
        if not isinstance(channels, list):
            logger.warning("Channels for event '%s' must be a list, got %s. Dropping.", event, type(channels))
            continue
        kept = [c for c in channels if c in _VALID_CHANNELS]
        if len(kept) != len(channels):
            logger.warning("Dropped invalid channels for '%s': %s", event, set(channels) - _VALID_CHANNELS)
        if kept:
            cleaned[event] = kept
    return cleaned


# Every declaration of the {event: [channels]} structure uses this, so a preference cannot be
# accepted and echoed back by a request schema only to be dropped when the model reads it.
NotificationPreferences = Annotated[
    dict[str, list[str]] | None,
    AfterValidator(sanitize_notification_preferences),
]
