"""Unit tests for WebhookService._format_payload and test_webhook."""

import json
import pytest

from unittest.mock import AsyncMock, MagicMock, patch

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
    """Mirror the flat payload built by audit.history._dispatch_webhook:
    top-level project_id/actor/change_summary, no nested project/scan."""
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
        result = service._format_payload(webhook, "scan.completed", raw)
        assert result is raw

    def test_returns_raw_for_all_event_types(self):
        service = WebhookService()
        webhook = make_webhook("generic")
        for event in ["vulnerability.found", "analysis.failed", "test", "sbom.ingested"]:
            raw = {"event": event, "scan": {}, "project": {}}
            result = service._format_payload(webhook, event, raw)
            assert result is raw


class TestFormatPayloadTeamsWebhook:
    def test_scan_completed_returns_adaptive_card(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook, "scan.completed", make_scan_payload())
        assert result["type"] == "message"
        assert result["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

    def test_vulnerability_found_returns_adaptive_card(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook, "vulnerability.found", make_vuln_payload())
        assert result["type"] == "message"
        assert result["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

    def test_analysis_failed_returns_adaptive_card(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook, "analysis.failed", make_failed_payload())
        assert result["type"] == "message"
        card = result["attachments"][0]["content"]
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "attention"

    def test_test_event_returns_test_card(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook, "test", {"event": "test", "scan": {}, "project": {}})
        assert result["type"] == "message"
        card = result["attachments"][0]["content"]
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "accent"

    def test_generic_fallback_for_unknown_event(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        raw = {"event": "sbom.ingested", "scan": {"id": "s1", "url": None}, "project": {"id": "p1", "name": "Proj"}}
        result = service._format_payload(webhook, "sbom.ingested", raw)
        assert result["type"] == "message"

    def test_scan_completed_snake_case_alias_also_works(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook, "scan_completed", make_scan_payload())
        assert result["type"] == "message"
        assert result["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"


class TestFormatPayloadPolicyEvents:
    """Policy-changed events use a flat payload (no nested project/scan). The
    Teams card must surface the actor, change summary and scope rather than
    falling through to an empty 'Unknown Project' generic card."""

    def _card_text(self, result: dict) -> str:
        assert result["type"] == "message"
        card = result["attachments"][0]["content"]
        return " ".join(b.get("text", "") for b in card["body"])

    def test_crypto_policy_changed_card_has_details(self):
        service = WebhookService()
        webhook = make_webhook("teams")
        result = service._format_payload(webhook, "crypto_policy.changed", make_policy_payload())
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
        result = service._format_payload(webhook, "license_policy.changed", payload)
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
        result = service._format_payload(webhook, "crypto_policy.changed", payload)
        text = self._card_text(result)
        assert "A user" in text
        assert "Policy updated" in text

    def test_generic_webhook_returns_raw_policy_payload(self):
        service = WebhookService()
        webhook = make_webhook("generic")
        raw = make_policy_payload()
        result = service._format_payload(webhook, "crypto_policy.changed", raw)
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
    """safe_trigger_webhooks is the single source of non-blocking semantics;
    trigger_webhooks itself may propagate an unexpected dispatch error."""

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
            # Must not raise.
            await service.safe_trigger_webhooks(MagicMock(), "scan.completed", {}, "p1", context="test")


def _make_mock_http_client(status_code: int = 200):
    """Return a mock InstrumentedAsyncClient context manager with the given response status."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)
    return mock_client


class TestTestWebhookForTeams:
    """Verify that test_webhook() sends the accent-styled test card for Teams webhooks."""

    @pytest.mark.asyncio
    async def test_sends_test_card_regardless_of_event_type(self):
        webhook = make_webhook("teams")
        webhook.url = "https://example.test/teams-hook"

        mock_client = _make_mock_http_client()

        with (
            patch("app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=None)),
            patch("app.services.webhooks.webhook_service.InstrumentedAsyncClient", return_value=mock_client),
        ):
            service = WebhookService()
            result = await service.test_webhook(webhook)

        assert result["success"] is True
        sent = json.loads(mock_client.post.call_args.kwargs["content"])
        assert sent["type"] == "message"
        card = sent["attachments"][0]["content"]
        container = next(b for b in card["body"] if b["type"] == "Container")
        assert container["style"] == "accent"

    @pytest.mark.asyncio
    async def test_generic_webhook_sends_raw_scan_payload(self):
        webhook = make_webhook("generic")
        webhook.url = "https://example.test/generic-hook"

        mock_client = _make_mock_http_client()

        with (
            patch("app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=None)),
            patch("app.services.webhooks.webhook_service.InstrumentedAsyncClient", return_value=mock_client),
        ):
            service = WebhookService()
            result = await service.test_webhook(webhook)

        assert result["success"] is True
        sent = json.loads(mock_client.post.call_args.kwargs["content"])
        assert sent.get("event") == "scan.completed"
        assert "attachments" not in sent
