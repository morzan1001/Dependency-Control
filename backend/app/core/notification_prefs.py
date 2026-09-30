"""The {event: [channels]} preference types: requests reject unknown names, stored documents drop them."""

import logging
from typing import Annotated

from pydantic import AfterValidator

from app.core.constants import NOTIFICATION_CHANNELS, NOTIFICATION_EVENTS

logger = logging.getLogger(__name__)

_VALID_CHANNELS = set(NOTIFICATION_CHANNELS)


def sanitize_notification_preferences(value: dict[str, list[str]] | None) -> dict[str, list[str]]:
    """Drop unknown events and channels; an event stored with no channels stays, as a mute."""
    cleaned: dict[str, list[str]] = {}
    for event, channels in (value or {}).items():
        kept = [c for c in channels if c in _VALID_CHANNELS]
        if event not in NOTIFICATION_EVENTS or len(kept) != len(channels):
            logger.warning("Dropped unknown notification preference %s: %s", event, channels)
        # Only a list stored empty is a mute; one that named nothing but retired channels is dropped.
        if event in NOTIFICATION_EVENTS and (kept or not channels):
            cleaned[event] = kept
    return cleaned


def validate_notification_preferences(value: dict[str, list[str]] | None) -> dict[str, list[str]]:
    value = value or {}
    events = set(value) - NOTIFICATION_EVENTS
    channels = {c for cs in value.values() for c in cs} - _VALID_CHANNELS
    if events or channels:
        raise ValueError(f"Unknown notification events {sorted(events)} or channels {sorted(channels)}")
    return value


NotificationPreferences = Annotated[
    dict[str, list[str]] | None,
    AfterValidator(sanitize_notification_preferences),
]
StrictNotificationPreferences = Annotated[
    dict[str, list[str]] | None,
    AfterValidator(validate_notification_preferences),
]
