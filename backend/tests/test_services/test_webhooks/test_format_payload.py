"""Unit tests for WebhookService._format_payload and test_webhook."""

import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.models.webhook import Webhook
from app.services.webhooks.webhook_service import WebhookService


def make_webhook(webhook_type: str) -> Webhook:
    return Webhook(
        url="https://example.com/hook",
        events=["scan.completed"],
        webhook_type=webhook_type,
    )


def make_scan_payload(project_name="TestProject", total=3):
    return {
        "event": "scan.completed",
        "timestamp": "2026-05-04T10:00:00Z",
        "scan": {"id": "scan-abc", "url": "https://app.example.com/scans/abc"},
        "project": {"id": "proj-1", "name": project_name},
        "findings": {"total": total, "stats": {"critical": 1}},
    }


def make_vuln_payload():
    return {
        "event": "vulnerability.found",
        "timestamp": "2026-05-04T10:00:00Z",
        "scan": {"id": "scan-abc", "url": None},
        "project": {"id": "proj-1", "name": "TestProject"},
        "vulnerabilities": {"critical": 2, "high": 1, "kev": 0, "high_epss": 0, "top": []},
    }


def make_failed_payload():
    return {
        "event": "analysis.failed",
        "timestamp": "2026-05-04T10:00:00Z",
        "scan": {"id": "scan-abc", "url": None},
        "project": {"id": "proj-1", "name": "TestProject"},
        "error": "SBOM parsing failed",
    }


def make_policy_payload(event="crypto_policy.changed"):
    """Flat policy payload: top-level project_id/actor/change_summary, no nested project/scan."""
    return {
        "event": event,
        "timestamp": "2026-05-04T10:00:00Z",
        "policy_type": "crypto",
        "policy_scope": "project",
        "project_id": "proj-42",
        "version": 7,
        "action": "update",
        "actor": {"user_id": "u1", "display_name": "Alice"},
        "change_summary": "Disallowed MD5",
        "comment": None,
        "reverted_from_version": None,
    }


class TestFormatPayloadGenericWebhook:
    def test_returns_raw_payload_unchanged(self):
        service = WebhookService()
        webhook = make_webhook("generic")
        raw = make_scan_payload()
        result = service._format_payload(webhook.webhook_type, "scan.completed", raw)
        assert result is raw

    def test_returns_raw_for_all_event_types(self):
        service = WebhookService()
        webhook = make_webhook("generic")
        for event in ["vulnerability.found", "analysis.failed", "test", "sbom.ingested"]:
            raw = {"event": event, "scan": {}, "project": {}}
            result = service._format_payload(webhook.webhook_type, event, raw)
            assert result is raw


class TestFormatPayloadTeamsWebhook:
    def test_scan_completed_returns_adaptive_card(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook.webhook_type, "scan.completed", make_scan_payload())
        assert result["type"] == "message"
        assert result["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

    def test_vulnerability_found_returns_adaptive_card(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook.webhook_type, "vulnerability.found", make_vuln_payload())
        assert result["type"] == "message"
        assert result["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

    def test_analysis_failed_returns_adaptive_card(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook.webhook_type, "analysis.failed", make_failed_payload())
        assert result["type"] == "message"
        card = result["attachments"][0]["content"]
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "attention"

    def test_generic_fallback_for_unknown_event(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        raw = {"event": "sbom.ingested", "scan": {"id": "s1", "url": None}, "project": {"id": "p1", "name": "Proj"}}
        result = service._format_payload(webhook.webhook_type, "sbom.ingested", raw)
        assert result["type"] == "message"


class TestFormatPayloadPolicyEvents:
    """Flat policy payloads must render a detailed Teams card, not the generic 'Unknown Project' fallback."""

    def _card_text(self, result: dict) -> str:
        assert result["type"] == "message"
        card = result["attachments"][0]["content"]
        return " ".join(b.get("text", "") for b in card["body"])

    def test_crypto_policy_changed_card_has_details(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook.webhook_type, "crypto_policy.changed", make_policy_payload())
        text = self._card_text(result)
        assert "Crypto Policy Changed" in text
        assert "Alice" in text
        assert "Disallowed MD5" in text
        assert "proj-42" in text
        assert "version 7" in text
        assert "Unknown Project" not in text

    def test_license_policy_changed_system_scope(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        payload = make_policy_payload("license_policy.changed")
        payload["policy_type"] = "license"
        payload["policy_scope"] = "system"
        payload["project_id"] = None
        result = service._format_payload(webhook.webhook_type, "license_policy.changed", payload)
        text = self._card_text(result)
        assert "License Policy Changed" in text
        assert "system" in text
        assert "Unknown Project" not in text

    def test_policy_card_falls_back_when_actor_missing(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        payload = make_policy_payload()
        payload["actor"] = None
        payload["change_summary"] = ""
        result = service._format_payload(webhook.webhook_type, "crypto_policy.changed", payload)
        text = self._card_text(result)
        assert "A user" in text
        assert "Policy updated" in text

    def test_generic_webhook_returns_raw_policy_payload(self):
        service = WebhookService()
        webhook = make_webhook("generic")
        raw = make_policy_payload()
        result = service._format_payload(webhook.webhook_type, "crypto_policy.changed", raw)
        assert result is raw


class TestLogWebhookDeliveryProjectId:
    @pytest.mark.asyncio
    async def test_flat_project_id_used_for_policy_events(self):
        service = WebhookService()
        captured = {}

        class FakeRepo:
            def __init__(self, db):
                pass

            async def log_delivery(self, **kwargs):
                captured.update(kwargs)

        with patch("app.repositories.webhook_deliveries.WebhookDeliveriesRepository", FakeRepo):
            await service._log_webhook_delivery(
                db=MagicMock(),
                webhook_id="w1",
                event_type="crypto_policy.changed",
                payload=make_policy_payload(),
                success=True,
            )

        assert captured["payload_summary"]["project_id"] == "proj-42"
        assert captured["payload_summary"]["scan_id"] is None

    @pytest.mark.asyncio
    async def test_nested_project_id_still_used_for_scan_events(self):
        service = WebhookService()
        captured = {}

        class FakeRepo:
            def __init__(self, db):
                pass

            async def log_delivery(self, **kwargs):
                captured.update(kwargs)

        with patch("app.repositories.webhook_deliveries.WebhookDeliveriesRepository", FakeRepo):
            await service._log_webhook_delivery(
                db=MagicMock(),
                webhook_id="w1",
                event_type="scan.completed",
                payload=make_scan_payload(),
                success=True,
            )

        assert captured["payload_summary"]["project_id"] == "proj-1"
        assert captured["payload_summary"]["scan_id"] == "scan-abc"


class TestNonBlockingSemantics:
    """Only safe_trigger_webhooks swallows errors; trigger_webhooks propagates them."""

    @pytest.mark.asyncio
    async def test_trigger_webhooks_propagates_internal_error(self):
        service = WebhookService()
        with patch.object(service, "_get_webhooks_for_event", new=AsyncMock(side_effect=RuntimeError("boom"))):
            with pytest.raises(RuntimeError):
                await service.trigger_webhooks(MagicMock(), "scan.completed", {}, "p1")

    @pytest.mark.asyncio
    async def test_safe_trigger_webhooks_swallows_errors(self):
        service = WebhookService()
        with patch.object(service, "trigger_webhooks", new=AsyncMock(side_effect=RuntimeError("boom"))):
            await service.safe_trigger_webhooks(MagicMock(), "scan.completed", {}, "p1", context="test")


async def _streamed(body: bytes) -> AsyncIterator[bytes]:
    # MockTransport pre-reads bytes content; a real receiver's answer arrives as a stream.
    yield body


def _recording_transport(status_code: int = 200, body: bytes = b"") -> tuple[httpx.MockTransport, list[httpx.Request]]:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(status_code, content=_streamed(body))

    return httpx.MockTransport(handler), sent


class TestTestWebhookForTeams:
    @pytest.mark.asyncio
    async def test_sends_test_card_regardless_of_event_type(self):
        webhook = make_webhook("teams")
        webhook.url = "https://example.test/teams-hook"

        transport, requests = _recording_transport()

        with patch(
            "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
        ):
            result = await WebhookService().test_webhook(webhook)

        assert result["success"] is True
        sent = json.loads(requests[0].content)
        assert sent["type"] == "message"
        card = sent["attachments"][0]["content"]
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "accent"

    @pytest.mark.asyncio
    async def test_a_teams_url_stored_as_generic_gets_the_test_card(self):
        webhook = make_webhook("generic")
        webhook.url = "https://tenant.webhook.office.com/webhookb2/abc"

        transport, requests = _recording_transport()

        with patch(
            "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
        ):
            await WebhookService().test_webhook(webhook)

        card = json.loads(requests[0].content)["attachments"][0]["content"]
        assert next(b for b in card["body"] if b["type"] == "Container")["style"] == "accent"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("webhook_type", ["teams", "generic"])
    async def test_the_signature_covers_the_body_that_is_sent(self, webhook_type):
        webhook = make_webhook(webhook_type)
        webhook.url = "https://example.test/hook"
        webhook.secret = "s3cret"
        service = WebhookService()

        transport, requests = _recording_transport()

        with patch(
            "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
        ):
            await service.test_webhook(webhook)

        signed = service._generate_signature("s3cret", requests[0].content.decode())
        assert requests[0].headers["X-Webhook-Signature"] == f"sha256={signed}"

    @pytest.mark.asyncio
    async def test_generic_webhook_sends_raw_scan_payload(self):
        webhook = make_webhook("generic")
        webhook.url = "https://example.test/generic-hook"

        transport, requests = _recording_transport()

        with patch(
            "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
        ):
            result = await WebhookService().test_webhook(webhook)

        assert result["success"] is True
        sent = json.loads(requests[0].content)
        assert sent.get("event") == "scan.completed"
        assert "attachments" not in sent

    @pytest.mark.asyncio
    async def test_a_non_2xx_answer_reports_the_status_and_body(self):
        webhook = make_webhook("generic")
        webhook.url = "https://example.test/generic-hook"

        transport, _ = _recording_transport(status_code=503, body=b"down for maintenance")

        with patch(
            "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
        ):
            result = await WebhookService().test_webhook(webhook)

        assert (result["success"], result["status_code"], result["error"]) == (
            False,
            503,
            "HTTP 503: down for maintenance",
        )


class TestDeliverySignature:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("webhook_type", "url"),
        [("teams", "https://example.test/teams-hook"), ("generic", "https://tenant.webhook.office.com/webhookb2/abc")],
    )
    async def test_a_teams_delivery_is_signed_over_the_card_it_transmits(self, webhook_type, url):
        webhook = make_webhook(webhook_type)
        webhook.url = url
        webhook.secret = "s3cret"
        service = WebhookService(timeout=1.0, max_retries=1)
        transport, requests = _recording_transport()

        with (
            patch(
                "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
            ),
            patch.object(service, "_update_webhook_status", new=AsyncMock()),
            patch.object(service, "_log_webhook_delivery", new=AsyncMock()),
        ):
            delivered = await service._send_webhook(MagicMock(), webhook, make_scan_payload(), "scan.completed")

        body = requests[0].content
        expected = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        assert delivered is True
        assert json.loads(body)["type"] == "message"
        assert requests[0].headers["X-Webhook-Signature"] == f"sha256={expected}"
