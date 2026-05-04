"""Unit tests for WebhookService._format_payload."""

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
