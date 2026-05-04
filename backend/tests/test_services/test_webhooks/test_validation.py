"""Tests for webhook URL and event validation."""

from unittest.mock import patch

import pytest

from app.services.webhooks.validation import (
    assert_safe_webhook_target,
    detect_webhook_type,
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

    def test_http_ipv6_loopback_passes(self):
        result = validate_webhook_url("http://[::1]:8080/hook")
        assert result == "http://[::1]:8080/hook"

    def test_http_non_localhost_raises(self):
        with pytest.raises(ValueError, match="Plain HTTP"):
            validate_webhook_url("http://example.com/webhook")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_webhook_url("")

    def test_ftp_url_raises(self):
        with pytest.raises(ValueError, match="scheme"):
            validate_webhook_url("ftp://example.com/webhook")

    def test_no_protocol_raises(self):
        with pytest.raises(ValueError, match="scheme"):
            validate_webhook_url("example.com/webhook")

    def test_userinfo_bypass_rejected(self):
        with pytest.raises(ValueError, match="Plain HTTP"):
            validate_webhook_url("http://localhost@evil.com/hook")

    def test_userinfo_bypass_with_127_rejected(self):
        with pytest.raises(ValueError, match="Plain HTTP"):
            validate_webhook_url("http://127.0.0.1@evil.com/hook")

    def test_suffix_bypass_rejected(self):
        with pytest.raises(ValueError, match="Plain HTTP"):
            validate_webhook_url("http://localhost.evil.com/hook")

    def test_suffix_bypass_127_rejected(self):
        with pytest.raises(ValueError, match="Plain HTTP"):
            validate_webhook_url("http://127.0.0.1.evil.com/hook")

    def test_uppercase_https_passes(self):
        result = validate_webhook_url("HTTPS://example.com/hook")
        assert result == "HTTPS://example.com/hook"

    @pytest.mark.parametrize(
        "url",
        [
            "https://192.168.1.1/admin",
            "https://10.0.0.5/hook",
            "https://172.16.0.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://[fc00::1]/hook",
            "https://[fe80::1]/hook",
            "https://0.0.0.0/hook",
            "https://224.0.0.1/hook",
        ],
    )
    def test_private_and_reserved_ip_literals_rejected(self, url):
        with pytest.raises(ValueError, match="private|reserved|link-local"):
            validate_webhook_url(url)

    @pytest.mark.parametrize(
        "host",
        [
            "metadata.google.internal",
            "metadata.goog",
            "metadata",
        ],
    )
    def test_blocked_metadata_hostnames_rejected(self, host):
        with pytest.raises(ValueError, match="not an allowed target"):
            validate_webhook_url(f"https://{host}/latest/meta-data/")

    def test_localhost_disabled_via_setting(self):
        with patch("app.services.webhooks.validation.settings") as s:
            s.WEBHOOK_ALLOW_LOCALHOST = False
            with pytest.raises(ValueError, match="Localhost"):
                validate_webhook_url("http://localhost:8080/hook")
            with pytest.raises(ValueError, match="Localhost"):
                validate_webhook_url("http://127.0.0.1/hook")


class TestValidateWebhookUrlOptional:
    def test_none_returns_none(self):
        assert validate_webhook_url_optional(None) is None

    def test_valid_url_passes(self):
        result = validate_webhook_url_optional("https://example.com/hook")
        assert result == "https://example.com/hook"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            validate_webhook_url_optional("http://example.com/hook")


class TestAssertSafeWebhookTarget:
    @pytest.mark.asyncio
    async def test_loopback_host_skipped(self):
        await assert_safe_webhook_target("http://localhost:8080/hook")
        await assert_safe_webhook_target("http://127.0.0.1/hook")
        await assert_safe_webhook_target("http://[::1]/hook")

    @pytest.mark.asyncio
    async def test_blocked_ip_literal_rejected(self):
        with pytest.raises(ValueError, match="blocked IP range"):
            await assert_safe_webhook_target("https://192.168.1.1/hook")

    @pytest.mark.asyncio
    async def test_resolved_to_private_ip_rejected(self):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("10.0.0.5", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            with pytest.raises(ValueError, match="resolves to"):
                await assert_safe_webhook_target("https://attacker.example.com/hook")

    @pytest.mark.asyncio
    async def test_resolved_to_metadata_ip_rejected(self):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("169.254.169.254", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            with pytest.raises(ValueError, match="resolves to"):
                await assert_safe_webhook_target("https://metadata-spoof.example.com/")

    @pytest.mark.asyncio
    async def test_resolved_to_public_ip_passes(self):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("93.184.216.34", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            await assert_safe_webhook_target("https://example.com/hook")


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


class TestDetectWebhookType:
    def test_classic_teams_incoming_webhook(self):
        url = "https://contoso.webhook.office.com/webhookb2/abc123/IncomingWebhook/xyz"
        assert detect_webhook_type(url) == "teams"

    def test_teams_subdomain_variant(self):
        url = "https://outlook.webhook.office.com/webhookb2/abc"
        assert detect_webhook_type(url) == "teams"

    def test_power_automate_workflows_url(self):
        url = "https://prod-12.westeurope.logic.azure.com/workflows/abc123/triggers/manual/paths/invoke"
        assert detect_webhook_type(url) == "teams"

    def test_logic_azure_without_workflows_path(self):
        url = "https://management.logic.azure.com/something-else"
        assert detect_webhook_type(url) == "generic"

    def test_github_webhook(self):
        assert detect_webhook_type("https://smee.io/abc123") == "generic"

    def test_slack_webhook(self):
        assert detect_webhook_type("https://hooks.slack.com/services/T123/B456/xyz") == "generic"

    def test_generic_https_url(self):
        assert detect_webhook_type("https://my-server.example.com/webhook") == "generic"

    def test_office_com_non_webhook_subdomain_is_generic(self):
        # hostname ends with 'webhook.office.com' chars but has no separating dot
        assert detect_webhook_type("https://evilwebhook.office.com/abc") == "generic"

    def test_logic_azure_non_logic_subdomain_is_generic(self):
        # hostname ends with 'logic.azure.com' chars but has no separating dot
        assert detect_webhook_type("https://evil-logic.azure.com/workflows/abc") == "generic"

    def test_power_platform_automate_url(self):
        url = (
            "https://default047b2e1fa2714bc197a4703bf7adf1.35.environment.api.powerplatform.com"
            "/powerautomate/automations/direct/workflows/67fa2e06/triggers/manual/paths/invoke"
        )
        assert detect_webhook_type(url) == "teams"

    def test_power_platform_without_workflows_path(self):
        url = "https://api.powerplatform.com/other/path"
        assert detect_webhook_type(url) == "generic"

    def test_empty_string_returns_generic(self):
        assert detect_webhook_type("") == "generic"
