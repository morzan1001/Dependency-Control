"""Tests for Webhook model."""

import pytest
from pydantic import ValidationError

from app.models.webhook import Webhook


class TestWebhookModel:
    def test_minimal_valid(self):
        webhook = Webhook(
            url="https://example.com/hook",
            events=["scan_completed"],
        )
        assert webhook.url == "https://example.com/hook"
        assert "scan_completed" in webhook.events

    def test_defaults(self):
        webhook = Webhook(
            url="https://example.com/hook",
            events=["scan_completed"],
        )
        assert webhook.project_id is None
        assert webhook.secret is None
        assert webhook.headers is None
        assert webhook.is_active is True
        assert webhook.consecutive_failures == 0
        assert webhook.circuit_breaker_until is None
        assert webhook.total_deliveries == 0
        assert webhook.total_failures == 0

    def test_project_scoped(self):
        webhook = Webhook(
            project_id="proj-1",
            url="https://example.com/hook",
            events=["scan_completed"],
        )
        assert webhook.project_id == "proj-1"

    def test_id_auto_generated(self):
        a = Webhook(url="https://a.com/hook", events=["scan_completed"])
        b = Webhook(url="https://b.com/hook", events=["scan_completed"])
        assert a.id != b.id

    def test_with_secret(self):
        webhook = Webhook(
            url="https://example.com/hook",
            events=["scan_completed"],
            secret="my-secret-key",
        )
        assert webhook.secret == "my-secret-key"

    def test_with_custom_headers(self):
        webhook = Webhook(
            url="https://example.com/hook",
            events=["scan_completed"],
            headers={"X-Custom": "value"},
        )
        assert webhook.headers == {"X-Custom": "value"}

    def test_empty_events_rejected(self):
        with pytest.raises((ValidationError, ValueError)):
            Webhook(url="https://example.com/hook", events=[])

    def test_invalid_event_rejected(self):
        with pytest.raises((ValidationError, ValueError)):
            Webhook(url="https://example.com/hook", events=["nonexistent.event.xyz"])

    def test_localhost_url_accepted(self):
        webhook = Webhook(
            url="http://localhost:8080/hook",
            events=["scan_completed"],
        )
        assert "localhost" in webhook.url


class TestWebhookSerialization:
    def test_id_alias(self):
        webhook = Webhook(
            url="https://example.com/hook",
            events=["scan_completed"],
        )
        dumped = webhook.model_dump(by_alias=True)
        assert "_id" in dumped
