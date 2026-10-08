"""Tests for Webhook model."""

import subprocess
import sys
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.core.config import settings
from app.models.webhook import Webhook
from app.schemas.webhook import WebhookCreate, WebhookResponse, WebhookUpdate


class TestWebhookModel:
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

    def test_a_request_without_events_is_rejected(self):
        with pytest.raises(ValidationError):
            WebhookCreate(url="https://example.com/hook", events=[])

    def test_a_request_naming_an_unknown_event_is_rejected(self):
        with pytest.raises(ValidationError):
            WebhookCreate(url="https://example.com/hook", events=["nonexistent.event.xyz"])

    def test_localhost_url_accepted(self):
        webhook = Webhook(
            url="http://localhost:8080/hook",
            events=["scan_completed"],
        )
        assert "localhost" in webhook.url


class TestWebhookTypeField:
    def test_defaults_to_generic(self):
        webhook = Webhook(url="https://example.com/hook", events=["scan_completed"])
        assert webhook.webhook_type == "generic"

    def test_accepts_teams(self):
        webhook = Webhook(
            url="https://example.com/hook",
            events=["scan_completed"],
            webhook_type="teams",
        )
        assert webhook.webhook_type == "teams"

    def test_rejects_unknown_type(self):
        with pytest.raises(ValidationError):
            Webhook(
                url="https://example.com/hook",
                events=["scan_completed"],
                webhook_type="discord",
            )


class TestWebhookCreateSchemaType:
    def test_webhook_type_optional_defaults_none(self):
        schema = WebhookCreate(url="https://example.com/hook", events=["scan_completed"])
        assert schema.webhook_type is None

    def test_webhook_type_accepts_teams(self):
        schema = WebhookCreate(
            url="https://example.com/hook",
            events=["scan_completed"],
            webhook_type="teams",
        )
        assert schema.webhook_type == "teams"

    def test_webhook_type_accepts_generic(self):
        schema = WebhookCreate(
            url="https://example.com/hook",
            events=["scan_completed"],
            webhook_type="generic",
        )
        assert schema.webhook_type == "generic"

    def test_webhook_type_rejects_unknown(self):
        with pytest.raises(ValidationError):
            WebhookCreate(
                url="https://example.com/hook",
                events=["scan_completed"],
                webhook_type="pagerduty",
            )

    def test_webhook_response_includes_type(self):
        resp = WebhookResponse(
            id="abc",
            url="https://example.com/hook",
            events=["scan_completed"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
            webhook_type="teams",
        )
        assert resp.webhook_type == "teams"

    def test_webhook_update_rejects_unknown_type(self):
        with pytest.raises(ValidationError):
            WebhookUpdate(webhook_type="pagerduty")


class TestWebhookUpdateNulls:
    @pytest.mark.parametrize("field", ["url", "events", "is_active", "webhook_type"])
    def test_an_explicit_null_for_a_field_the_stored_model_requires_is_rejected(self, field):
        with pytest.raises(ValidationError, match="cannot be null"):
            WebhookUpdate(**{field: None})

    @pytest.mark.parametrize("field", ["secret", "headers"])
    def test_an_explicit_null_clears_the_secret_or_the_headers(self, field):
        assert WebhookUpdate(**{field: None}).model_dump(exclude_unset=True) == {field: None}

    def test_a_legacy_event_name_is_stored_in_its_canonical_form(self):
        update = WebhookUpdate(events=["scan_completed", "scan.completed", "vulnerability_found"])
        assert update.events == ["scan.completed", "vulnerability.found"]


class TestWebhookHeaders:
    @pytest.mark.parametrize("schema", [WebhookCreate, WebhookUpdate])
    def test_ordinary_custom_headers_are_kept(self, schema):
        headers = {"Authorization": "Bearer abc", "X-Team": "Müller"}
        model = schema(url="https://example.com/hook", events=["scan_completed"], headers=headers)
        assert model.headers == headers

    @pytest.mark.parametrize("schema", [WebhookCreate, WebhookUpdate])
    @pytest.mark.parametrize(
        "headers",
        [
            {"X-Evil": "a\r\nX-Injected: 1"},
            {"X-Evil": "a\nb"},
            {"Bad Name": "x"},
            {"X-Team": "€"},
            {"X-Team": " padded"},
            {"content-type": "text/plain"},
            {"HOST": "internal"},
            {"X-Webhook-Signature": "forged"},
            {"x-webhook-delivery": "replayed"},
        ],
    )
    def test_headers_that_would_break_or_forge_the_request_are_rejected(self, schema, headers):
        with pytest.raises(ValidationError):
            schema(url="https://example.com/hook", events=["scan_completed"], headers=headers)


class TestWebhookUrlHost:
    def test_a_loopback_address_spelled_with_ideographic_full_stops_is_still_loopback(self):
        with (
            patch.object(settings, "WEBHOOK_ALLOW_LOCALHOST", False),
            pytest.raises(ValidationError, match="Localhost"),
        ):
            WebhookCreate(url="https://127。0。0。1/hook", events=["scan_completed"])

    def test_a_host_that_is_not_valid_idna_is_rejected(self):
        with pytest.raises(ValidationError, match="Invalid URL"):
            WebhookCreate(url="https://\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com/hook", events=["scan_completed"])


def test_webhook_schemas_load_no_service_module():
    loaded = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, app.schemas.webhook; print(sorted(m for m in sys.modules if m.startswith('app.services')))",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert loaded == "[]"
