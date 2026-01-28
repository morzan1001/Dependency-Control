"""
Webhook model for MongoDB storage.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from app.services.webhooks.validation import (
    validate_webhook_events,
    validate_webhook_url,
)


class Webhook(BaseModel):
    """
    Webhook configuration for event notifications.

    Attributes:
        id: Unique identifier (MongoDB _id)
        project_id: Associated project ID, None for global webhooks
        url: Target URL for webhook delivery
        events: List of event types to subscribe to
        secret: Optional secret for HMAC signature verification (not returned in API responses)
        headers: Optional custom headers to include in requests
        is_active: Whether the webhook is enabled
        created_at: Creation timestamp
        last_triggered_at: Last successful delivery timestamp
        last_failure_at: Last failed delivery timestamp
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: Optional[str] = None
    url: str
    events: List[str]
    secret: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_triggered_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: List[str]) -> List[str]:
        """Validate that all events are valid and list is not empty."""
        return validate_webhook_events(v, allow_empty=False)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        """Validate that URL is HTTPS (except for localhost in development)."""
        return validate_webhook_url(v)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
