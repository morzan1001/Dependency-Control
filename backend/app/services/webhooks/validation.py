"""
Shared validation functions for webhook URL and events.

These functions are used by both the Webhook model and schemas
to ensure consistent validation across the application.
"""

from typing import List, Optional

from app.core.constants import WEBHOOK_ALLOWED_URL_PREFIXES, WEBHOOK_VALID_EVENTS


def validate_webhook_url(url: str) -> str:
    """
    Validate that a webhook URL is valid and uses HTTPS.

    Args:
        url: The URL to validate

    Returns:
        The validated URL

    Raises:
        ValueError: If the URL is empty or doesn't use HTTPS
                   (except for localhost in development)
    """
    if not url:
        raise ValueError("URL cannot be empty")
    if not url.startswith(WEBHOOK_ALLOWED_URL_PREFIXES):
        raise ValueError("Webhook URL must use HTTPS (except for localhost)")
    return url


def validate_webhook_url_optional(url: Optional[str]) -> Optional[str]:
    """
    Validate an optional webhook URL.

    Args:
        url: The URL to validate, or None

    Returns:
        The validated URL or None

    Raises:
        ValueError: If the URL is provided but invalid
    """
    if url is None:
        return None
    return validate_webhook_url(url)


def validate_webhook_events(events: List[str], allow_empty: bool = False) -> List[str]:
    """
    Validate that all webhook events are valid event types.

    Args:
        events: List of event type strings to validate
        allow_empty: If False, raises error when events list is empty

    Returns:
        The validated events list

    Raises:
        ValueError: If any event is invalid or if the list is empty (when allow_empty=False)
    """
    if not allow_empty and not events:
        raise ValueError("At least one event type is required")

    invalid_events = [e for e in events if e not in WEBHOOK_VALID_EVENTS]
    if invalid_events:
        raise ValueError(
            f"Invalid event types: {invalid_events}. "
            f"Valid events: {WEBHOOK_VALID_EVENTS}"
        )
    return events


def validate_webhook_events_optional(
    events: Optional[List[str]],
) -> Optional[List[str]]:
    """
    Validate an optional list of webhook events.

    Args:
        events: List of event types to validate, or None

    Returns:
        The validated events list or None

    Raises:
        ValueError: If the events are provided but invalid
    """
    if events is None:
        return None
    return validate_webhook_events(events, allow_empty=False)


def validate_webhook_event_type(event_type: str) -> str:
    """
    Validate a single webhook event type.

    Args:
        event_type: The event type to validate

    Returns:
        The validated event type

    Raises:
        ValueError: If the event type is invalid
    """
    if event_type not in WEBHOOK_VALID_EVENTS:
        raise ValueError(
            f"Invalid event type: {event_type}. Valid events: {WEBHOOK_VALID_EVENTS}"
        )
    return event_type
