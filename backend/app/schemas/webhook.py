"""
Webhook API schemas for request/response validation.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, field_validator

from app.core.constants import WEBHOOK_EVENT_SCAN_COMPLETED
from app.services.webhooks.validation import (
    validate_webhook_event_type,
    validate_webhook_events,
    validate_webhook_events_optional,
    validate_webhook_url,
    validate_webhook_url_optional,
)


class WebhookCreate(BaseModel):
    """Schema for creating a new webhook."""

    url: str
    events: List[str]
    secret: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: List[str]) -> List[str]:
        """Validate that all events are valid event types."""
        return validate_webhook_events(v, allow_empty=False)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        """Validate that URL is HTTPS (except for localhost in development)."""
        return validate_webhook_url(v)


class WebhookUpdate(BaseModel):
    """Schema for updating an existing webhook."""

    url: Optional[str] = None
    events: Optional[List[str]] = None
    is_active: Optional[bool] = None
    secret: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate that all events are valid event types."""
        return validate_webhook_events_optional(v)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate that URL is HTTPS (except for localhost in development)."""
        return validate_webhook_url_optional(v)


class WebhookResponse(BaseModel):
    """Schema for webhook response (excludes secret for security)."""

    id: str
    project_id: Optional[str] = None
    url: str
    events: List[str]
    headers: Optional[Dict[str, str]] = None
    is_active: bool
    created_at: datetime
    last_triggered_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WebhookTestRequest(BaseModel):
    """Schema for testing a webhook."""

    event_type: str = WEBHOOK_EVENT_SCAN_COMPLETED

    @field_validator("event_type")
    @classmethod
    def _validate_event_type(cls, v: str) -> str:
        """Validate that the event type is valid."""
        return validate_webhook_event_type(v)


class WebhookTestResponse(BaseModel):
    """Schema for webhook test response."""

    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    response_time_ms: Optional[float] = None
