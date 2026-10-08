"""Unit tests for WebhookService._format_payload and test_webhook."""

import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.constants import WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED, WEBHOOK_EVENT_LICENSE_POLICY_CHANGED
from app.models.policy_audit_entry import PolicyAuditEntry
from app.models.stats import Stats
from app.models.webhook import Webhook
from app.schemas.policy_audit import PolicyAuditAction
from app.services.audit import history
from app.services.webhooks import webhook_service
from app.services.webhooks.webhook_service import WebhookService
from tests.helpers.webhooks import delivered


def make_webhook(webhook_type: str) -> Webhook:
    return Webhook(
        url="https://example.com/hook",
        events=["scan.completed"],
        webhook_type=webhook_type,
    )


async def _scan_payload() -> dict:
    _event, payload = await delivered(
        webhook_service.trigger_scan_completed(
            MagicMock(), "scan-abc", "proj-1", "TestProject", 3, Stats(critical=1).model_dump(), "completed", []
        )
    )
    return payload


def _policy_entry(**overrides) -> PolicyAuditEntry:
    fields = {
        "policy_type": "crypto",
        "policy_scope": "project",
        "project_id": "proj-42",
        "version": 7,
        "action": PolicyAuditAction.UPDATE,
        "actor_user_id": "u1",
        "actor_display_name": "Alice",
        "snapshot": {},
        "change_summary": "Disallowed MD5",
    }
    return PolicyAuditEntry(**{**fields, **overrides})


async def _policy_payload(entry: PolicyAuditEntry) -> dict:
    _event, payload = await delivered(history._dispatch_webhook(MagicMock(), entry))
    return payload


async def _vulnerability_payload() -> dict:
    top = {"id": "CVE-2021-44228", "severity": "CRITICAL", "package": "log4j-core", "version": "2.14.1", "in_kev": True}
    _event, payload = await delivered(
        webhook_service.trigger_vulnerability_found(
            MagicMock(), "scan-abc", "proj-1", "TestProject", 1, 0, 1, 0, 1, [top]
        )
    )
    return payload


async def _failed_payload() -> dict:
    _event, payload = await delivered(
        webhook_service.trigger_analysis_failed(MagicMock(), "scan-abc", "proj-1", "TestProject", "grype crashed")
    )
    return payload


class TestFormatPayloadSlackWebhook:
    """Slack's incoming webhooks answer a body without text with 400 no_text."""

    @pytest.mark.asyncio
    async def test_a_completed_scan_is_a_slack_message(self):
        message = WebhookService()._format_payload("slack", "scan.completed", await _scan_payload())
        assert "TestProject" in message["text"]
        assert message["blocks"][0]["type"] == "header"

    @pytest.mark.asyncio
    async def test_a_vulnerability_alert_names_its_top_vulnerability(self):
        message = WebhookService()._format_payload("slack", "vulnerability.found", await _vulnerability_payload())
        assert "TestProject" in message["text"]
        assert "CVE-2021-44228" in json.dumps(message["blocks"])

    @pytest.mark.asyncio
    async def test_a_failed_analysis_carries_its_error(self):
        message = WebhookService()._format_payload("slack", "analysis.failed", await _failed_payload())
        assert "TestProject" in message["text"]
        assert "grype crashed" in json.dumps(message["blocks"])

    @pytest.mark.asyncio
    async def test_the_notification_text_escapes_what_slack_reads_as_markup(self):
        _event, payload = await delivered(
            webhook_service.trigger_scan_completed(
                MagicMock(), "scan-abc", "proj-1", "<!channel> R&D", 3, Stats().model_dump(), "completed", []
            )
        )
        message = WebhookService()._format_payload("slack", "scan.completed", payload)
        assert "&lt;!channel&gt; R&amp;D" in message["text"]

    @pytest.mark.asyncio
    async def test_a_policy_change_names_the_actor_and_the_change(self):
        payload = await _policy_payload(_policy_entry())
        message = WebhookService()._format_payload("slack", WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED, payload)
        blocks = json.dumps(message["blocks"])
        assert message["text"]
        assert "Alice" in blocks and "Disallowed MD5" in blocks


_COMPLIANCE_PAYLOAD = {
    "event": "compliance_report.generated",
    "timestamp": "2026-10-08T10:00:00+00:00",
    "report_id": "r-1",
    "framework": "nist-800-53",
    "format": "pdf",
    "scope": "project",
    "scope_id": "proj-1",
    "status": "failed",
    "summary": None,
}
_SBOM_PAYLOAD = {
    "scan_id": "scan-abc",
    "project_id": "proj-1",
    "branch": "main",
    "sboms_processed": 2,
    "sboms_failed": 0,
}


class TestEventsWithoutAProjectObject:
    """SBOM, CBOM and compliance events carry flat fields; their message lists them instead of an unknown project."""

    @pytest.mark.parametrize("webhook_type", ["slack", "teams"])
    def test_a_failed_compliance_report_says_so(self, webhook_type):
        message = json.dumps(
            WebhookService()._format_payload(webhook_type, "compliance_report.generated", _COMPLIANCE_PAYLOAD)
        )
        assert "failed" in message
        assert "Unknown Project" not in message

    def test_an_ingested_sbom_names_its_project_in_the_slack_text(self):
        message = WebhookService()._format_payload("slack", "sbom.ingested", _SBOM_PAYLOAD)
        assert "proj-1" in message["text"]


class TestFormatPayloadGenericWebhook:
    @pytest.mark.asyncio
    async def test_returns_raw_payload_unchanged(self):
        raw = await _scan_payload()
        assert WebhookService()._format_payload("generic", "scan.completed", raw) is raw

    @pytest.mark.asyncio
    async def test_returns_raw_policy_payload(self):
        raw = await _policy_payload(_policy_entry())
        assert WebhookService()._format_payload("generic", "crypto_policy.changed", raw) is raw


class TestFormatPayloadPolicyEvents:
    """Flat policy payloads render a detailed Teams card, not the generic 'Unknown Project' fallback."""

    async def _card_text(self, entry: PolicyAuditEntry, event: str = WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED) -> str:
        result = WebhookService()._format_payload("teams", event, await _policy_payload(entry))
        card = result["attachments"][0]["content"]
        return " ".join(b.get("text", "") for b in card["body"])

    @pytest.mark.asyncio
    async def test_crypto_policy_changed_card_has_details(self):
        text = await self._card_text(_policy_entry())
        assert text == "Crypto Policy Changed Alice updated the project proj-42 policy: Disallowed MD5 (version 7)"

    @pytest.mark.asyncio
    async def test_license_policy_changed_system_scope(self):
        entry = _policy_entry(policy_type="license", policy_scope="system", project_id=None)
        text = await self._card_text(entry, WEBHOOK_EVENT_LICENSE_POLICY_CHANGED)
        assert text == "License Policy Changed Alice updated the system policy: Disallowed MD5 (version 7)"

    @pytest.mark.asyncio
    async def test_a_seeded_policy_names_no_actor(self):
        entry = _policy_entry(
            policy_scope="system",
            project_id=None,
            version=0,
            action=PolicyAuditAction.SEED,
            actor_user_id=None,
            actor_display_name=None,
            change_summary="Seeded defaults",
        )
        text = await self._card_text(entry)
        assert text == "Crypto Policy Changed A user updated the system policy: Seeded defaults (version 0)"


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

        with patch("app.services.webhooks.webhook_service.WebhookDeliveriesRepository", FakeRepo):
            await service._log_webhook_delivery(
                db=MagicMock(),
                webhook_id="w1",
                event_type="crypto_policy.changed",
                payload=await _policy_payload(_policy_entry()),
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

        with patch("app.services.webhooks.webhook_service.WebhookDeliveriesRepository", FakeRepo):
            await service._log_webhook_delivery(
                db=MagicMock(),
                webhook_id="w1",
                event_type="scan.completed",
                payload=await _scan_payload(),
                success=True,
            )

        assert captured["payload_summary"]["project_id"] == "proj-1"
        assert captured["payload_summary"]["scan_id"] == "scan-abc"


class TestNonBlockingSemantics:
    """trigger_webhooks propagates errors; safe_trigger_webhooks and the typed triggers swallow them."""

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

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "fire",
        [
            pytest.param(
                lambda s: s.trigger_scan_completed(MagicMock(), "s1", "p1", "P", 0, {}, "completed", []), id="scan"
            ),
            pytest.param(
                lambda s: s.trigger_vulnerability_found(MagicMock(), "s1", "p1", "P", 1, 0, 0, 0, 1, []), id="vuln"
            ),
            pytest.param(lambda s: s.trigger_analysis_failed(MagicMock(), "s1", "p1", "P", "boom"), id="failed"),
        ],
    )
    async def test_the_typed_triggers_swallow_a_failed_lookup(self, fire):
        service = WebhookService()
        with patch.object(service, "_get_webhooks_for_event", new=AsyncMock(side_effect=RuntimeError("boom"))):
            await fire(service)


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
    async def test_a_slack_webhook_test_sends_a_slack_message(self):
        webhook = make_webhook("slack")
        webhook.url = "https://hooks.slack.com/services/T0/B0/x"

        transport, requests = _recording_transport()

        with patch(
            "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
        ):
            result = await WebhookService().test_webhook(webhook)

        sent = json.loads(requests[0].content)
        assert result["success"] is True
        assert sent["text"] and sent["blocks"]

    @pytest.mark.asyncio
    async def test_a_teams_url_stored_as_generic_gets_the_raw_test_payload(self):
        webhook = make_webhook("generic")
        webhook.url = "https://tenant.webhook.office.com/webhookb2/abc"

        transport, requests = _recording_transport()

        with patch(
            "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
        ):
            await WebhookService().test_webhook(webhook)

        sent = json.loads(requests[0].content)
        assert (sent["test"], "attachments" in sent) == (True, False)

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
        ("webhook_type", "url", "shape"),
        [
            ("teams", "https://example.test/teams-hook", "message"),
            ("generic", "https://prod-1.westeurope.logic.azure.com/workflows/abc/triggers/manual", "scan.completed"),
        ],
    )
    async def test_the_stored_type_decides_the_body_and_the_signature_covers_it(self, webhook_type, url, shape):
        webhook = make_webhook(webhook_type)
        webhook.url = url
        webhook.secret = "s3cret"
        service = WebhookService(timeout=1.0, max_attempts=1)
        transport, requests = _recording_transport()

        with (
            patch(
                "app.services.webhooks.webhook_service.build_pinned_transport", new=AsyncMock(return_value=transport)
            ),
            patch.object(service, "_update_webhook_status", new=AsyncMock()),
            patch.object(service, "_log_webhook_delivery", new=AsyncMock()),
        ):
            sent = await service._send_webhook(MagicMock(), webhook, await _scan_payload(), "scan.completed")

        body = requests[0].content
        expected = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        assert sent is True
        assert json.loads(body).get("type", json.loads(body).get("event")) == shape
        assert requests[0].headers["X-Webhook-Signature"] == f"sha256={expected}"
