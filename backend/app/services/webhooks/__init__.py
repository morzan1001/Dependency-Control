"""Webhook triggering, validation, and typed payloads."""

from app.services.webhooks.types import (
    AnalysisFailedPayload,
    BaseWebhookPayload,
    FindingsStats,
    ProjectPayload,
    ScanCompletedPayload,
    ScanPayload,
    TestWebhookPayload,
    VulnerabilityFoundPayload,
    VulnerabilityInfo,
)
from app.services.webhooks.validation import (
    validate_webhook_event_type,
    validate_webhook_events,
    validate_webhook_events_optional,
    validate_webhook_url,
    validate_webhook_url_optional,
)
from app.services.webhooks.webhook_service import WebhookService, webhook_service

__all__ = [
    "AnalysisFailedPayload",
    "BaseWebhookPayload",
    "FindingsStats",
    "ProjectPayload",
    "ScanCompletedPayload",
    "ScanPayload",
    "TestWebhookPayload",
    "VulnerabilityFoundPayload",
    "VulnerabilityInfo",
    "WebhookService",
    "validate_webhook_event_type",
    "validate_webhook_events",
    "validate_webhook_events_optional",
    "validate_webhook_url",
    "validate_webhook_url_optional",
    "webhook_service",
]
