"""Tests for webhook URL and event validation."""

import pytest

from app.services.webhooks.validation import (
    validate_webhook_url,
    validate_webhook_url_optional,
    validate_webhook_events,
    validate_webhook_events_optional,
    validate_webhook_event_type,
)
from app.core.constants import WEBHOOK_VALID_EVENTS


class TestValidateWebhookUrl:
    def test_https_url_passes(self):
        result = validate_webhook_url("https://example.com/webhook")
        assert result == "https://example.com/webhook"

    def test_http_localhost_passes(self):
        result = validate_webhook_url("http://localhost:8080/hook")
        assert result == "http://localhost:8080/hook"

    def test_http_127_passes(self):
        result = validate_webhook_url("http://127.0.0.1:8080/hook")
        assert result == "http://127.0.0.1:8080/hook"

    def test_http_non_localhost_raises(self):
        with pytest.raises(ValueError, match="HTTPS"):
            validate_webhook_url("http://example.com/webhook")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_webhook_url("")

    def test_ftp_url_raises(self):
        with pytest.raises(ValueError, match="HTTPS"):
            validate_webhook_url("ftp://example.com/webhook")

    def test_no_protocol_raises(self):
        with pytest.raises(ValueError, match="HTTPS"):
            validate_webhook_url("example.com/webhook")


class TestValidateWebhookUrlOptional:
    def test_none_returns_none(self):
        assert validate_webhook_url_optional(None) is None

    def test_valid_url_passes(self):
        result = validate_webhook_url_optional("https://example.com/hook")
        assert result == "https://example.com/hook"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            validate_webhook_url_optional("http://example.com/hook")


class TestValidateWebhookEvents:
    def test_valid_single_event(self):
        result = validate_webhook_events(["scan_completed"])
        assert result == ["scan_completed"]

    def test_all_valid_events(self):
        result = validate_webhook_events(WEBHOOK_VALID_EVENTS)
        assert result == WEBHOOK_VALID_EVENTS

    def test_invalid_event_raises(self):
        with pytest.raises(ValueError, match="Invalid event"):
            validate_webhook_events(["invalid_event"])

    def test_mixed_valid_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid event"):
            validate_webhook_events(["scan_completed", "bogus_event"])

    def test_empty_list_raises_when_not_allowed(self):
        with pytest.raises(ValueError, match="At least one"):
            validate_webhook_events([], allow_empty=False)

    def test_empty_list_passes_when_allowed(self):
        result = validate_webhook_events([], allow_empty=True)
        assert result == []

    def test_multiple_valid_events(self):
        events = ["scan_completed", "vulnerability_found"]
        result = validate_webhook_events(events)
        assert result == events


class TestValidateWebhookEventsOptional:
    def test_none_returns_none(self):
        assert validate_webhook_events_optional(None) is None

    def test_valid_events_returned(self):
        result = validate_webhook_events_optional(["scan_completed"])
        assert result == ["scan_completed"]

    def test_invalid_events_raises(self):
        with pytest.raises(ValueError):
            validate_webhook_events_optional(["bogus"])


class TestValidateWebhookEventType:
    def test_valid_single_event(self):
        result = validate_webhook_event_type("scan_completed")
        assert result == "scan_completed"

    def test_invalid_single_event_raises(self):
        with pytest.raises(ValueError, match="Invalid event"):
            validate_webhook_event_type("bogus_event")
