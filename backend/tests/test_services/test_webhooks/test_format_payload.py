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
            patch("app.services.webhooks.webhook_service.assert_safe_webhook_target"),
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
            patch("app.services.webhooks.webhook_service.assert_safe_webhook_target"),
            patch("app.services.webhooks.webhook_service.InstrumentedAsyncClient", return_value=mock_client),
        ):
            service = WebhookService()
            result = await service.test_webhook(webhook)

        assert result["success"] is True
        sent = json.loads(mock_client.post.call_args.kwargs["content"])
        assert sent.get("event") == "scan.completed"
        assert "attachments" not in sent
