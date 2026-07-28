"""Webhook API schemas for request/response validation."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

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
    events: list[str]
    secret: str | None = None
    headers: dict[str, str] | None = None
    webhook_type: Literal["generic", "teams"] | None = None

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        """Validate that all events are valid event types."""
        return validate_webhook_events(v, allow_empty=False)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        """Validate that URL is HTTPS (except for localhost in development)."""
        return validate_webhook_url(v)


class WebhookUpdate(BaseModel):
    """Schema for updating an existing webhook."""

    url: str | None = None
    events: list[str] | None = None
    is_active: bool | None = None
    secret: str | None = None
    headers: dict[str, str] | None = None
    webhook_type: Literal["generic", "teams"] | None = None

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str] | None) -> list[str] | None:
        """Validate that all events are valid event types."""
        return validate_webhook_events_optional(v)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str | None) -> str | None:
        """Validate that URL is HTTPS (except for localhost in development)."""
        return validate_webhook_url_optional(v)


class WebhookResponse(BaseModel):
    """Schema for webhook response (excludes secret for security)."""

    id: str
    project_id: str | None = None
    team_id: str | None = None
    url: str
    events: list[str]
    headers: dict[str, str] | None = None
    is_active: bool
    created_at: datetime
    last_triggered_at: datetime | None = None
    last_failure_at: datetime | None = None
    webhook_type: Literal["generic", "teams"]

    model_config = ConfigDict(from_attributes=True)


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
    status_code: int | None = None
    error: str | None = None
    response_time_ms: float | None = None
