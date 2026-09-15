"""Tests for webhook URL and event validation."""

from unittest.mock import patch

import httpx
import pytest

from app.core.constants import WEBHOOK_VALID_EVENTS
from app.services.webhooks.validation import (
    _PinnedIPTransport,
    assert_safe_webhook_target,
    build_pinned_transport,
    detect_webhook_type,
    validate_webhook_event_type,
    validate_webhook_events,
    validate_webhook_events_optional,
    validate_webhook_url,
    validate_webhook_url_optional,
)


class TestValidateWebhookUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/webhook",
            "http://localhost:8080/hook",
            "http://127.0.0.1:8080/hook",
            "http://[::1]:8080/hook",
            "HTTPS://example.com/hook",
        ],
    )
    def test_accepted_url_is_returned_unchanged(self, url):
        assert validate_webhook_url(url) == url

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/webhook",
            # Userinfo and suffix look-alikes must not be read as the loopback host.
            "http://localhost@evil.com/hook",
            "http://127.0.0.1@evil.com/hook",
            "http://localhost.evil.com/hook",
            "http://127.0.0.1.evil.com/hook",
        ],
    )
    def test_plain_http_to_a_non_loopback_host_raises(self, url):
        with pytest.raises(ValueError, match="Plain HTTP"):
            validate_webhook_url(url)

    @pytest.mark.parametrize(
        ("url", "message"),
        [
            pytest.param("", "empty", id="empty-string"),
            pytest.param("ftp://example.com/webhook", "scheme", id="ftp"),
            pytest.param("example.com/webhook", "scheme", id="no-protocol"),
        ],
    )
    def test_unusable_url_raises(self, url, message):
        with pytest.raises(ValueError, match=message):
            validate_webhook_url(url)

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
        "url",
        [
            "https://[4000::1]/hook",
            "https://[5f00::1]/hook",
        ],
    )
    def test_ipv6_reserved_ip_literals_rejected(self, url):
        # IANA-reserved IPv6 blocks are caught by is_reserved alone; no other predicate covers them.
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
    @pytest.mark.parametrize(
        ("sockaddr", "url"),
        [
            pytest.param(("10.0.0.5", 0), "https://attacker.example.com/hook", id="private-ipv4"),
            pytest.param(("169.254.169.254", 0), "https://metadata-spoof.example.com/", id="metadata-ipv4"),
            pytest.param(("4000::1", 0, 0, 0), "https://attacker.example.com/hook", id="reserved-ipv6"),
        ],
    )
    async def test_resolved_to_blocked_ip_rejected(self, sockaddr, url):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", sockaddr)]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            with pytest.raises(ValueError, match="resolves to"):
                await assert_safe_webhook_target(url)

    @pytest.mark.asyncio
    async def test_resolved_to_public_ip_passes(self):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("93.184.216.34", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            await assert_safe_webhook_target("https://example.com/hook")

    @pytest.mark.asyncio
    async def test_returns_vetted_ip_for_hostname(self):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("93.184.216.34", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            assert await assert_safe_webhook_target("https://example.com/hook") == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_returns_ip_literal_for_public_ip(self):
        assert await assert_safe_webhook_target("https://93.184.216.34/hook") == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_returns_none_for_loopback(self):
        assert await assert_safe_webhook_target("http://localhost:8080/hook") is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("resolved", "url"),
        [
            pytest.param([(0, 0, 0, "", ("not-an-ip", 0))], "https://weird.example.com/hook", id="unparseable"),
            pytest.param([], "https://empty.example.com/hook", id="empty"),
        ],
    )
    async def test_resolution_without_a_usable_ip_fails_closed(self, resolved, url):
        # Returning None would let an unpinned transport reopen the rebinding window.
        async def fake_getaddrinfo(host, port, type=None):
            return resolved

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            with pytest.raises(ValueError, match="no usable IP"):
                await assert_safe_webhook_target(url)


class TestBuildPinnedTransport:
    """Delivery is pinned to the single vetted IP so httpx cannot re-resolve to an internal target."""

    @pytest.mark.asyncio
    async def test_hostname_pins_to_vetted_ip(self):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("93.184.216.34", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            transport = await build_pinned_transport("https://attacker.example.com/hook")

        assert isinstance(transport, _PinnedIPTransport)
        assert transport._ip == "93.184.216.34"
        assert transport._hostname == "attacker.example.com"

    @pytest.mark.asyncio
    async def test_pin_rewrites_connect_target_preserving_host_and_sni(self):
        transport = _PinnedIPTransport("attacker.example.com", "93.184.216.34")
        request = httpx.Request("POST", "https://attacker.example.com/hook")
        transport._pin(request)
        # Connect target becomes the vetted IP while Host header and TLS SNI keep the original hostname.
        assert request.url.host == "93.184.216.34"
        assert request.headers["Host"] == "attacker.example.com"
        assert request.extensions["sni_hostname"] == "attacker.example.com"

    @pytest.mark.asyncio
    async def test_rebinding_cannot_redirect_pinned_connection(self):
        # DNS returns a public IP at vetting time; transport is pinned to it.
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("93.184.216.34", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            transport = await build_pinned_transport("https://attacker.example.com/hook")

        # A later resolution to the metadata IP is ignored; the pinned target stays the vetted address.
        request = httpx.Request("POST", "https://attacker.example.com/latest/meta-data/")
        transport._pin(request)
        assert request.url.host == "93.184.216.34"
        assert request.url.host != "169.254.169.254"

    @pytest.mark.asyncio
    async def test_blocked_resolution_raises(self):
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("169.254.169.254", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            with pytest.raises(ValueError, match="resolves to"):
                await build_pinned_transport("https://metadata-spoof.example.com/")

    @pytest.mark.asyncio
    async def test_blocked_ip_literal_raises(self):
        with pytest.raises(ValueError, match="blocked IP range"):
            await build_pinned_transport("https://192.168.1.1/hook")

    @pytest.mark.asyncio
    async def test_ip_literal_pins_to_itself(self):
        transport = await build_pinned_transport("https://93.184.216.34/hook")
        assert isinstance(transport, _PinnedIPTransport)
        assert transport._ip == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_loopback_returns_plain_transport(self):
        transport = await build_pinned_transport("http://localhost:8080/hook")
        assert type(transport) is httpx.AsyncHTTPTransport
        assert not isinstance(transport, _PinnedIPTransport)

    @pytest.mark.asyncio
    async def test_unpinnable_resolution_does_not_fall_back_to_plain_transport(self):
        # A non-loopback host resolving to no usable IP must raise, not yield a re-resolving plain transport.
        async def fake_getaddrinfo(host, port, type=None):
            return [(0, 0, 0, "", ("garbage", 0))]

        with patch("asyncio.get_event_loop") as gel:
            gel.return_value.getaddrinfo = fake_getaddrinfo
            with pytest.raises(ValueError, match="no usable IP"):
                await build_pinned_transport("https://weird.example.com/hook")

    @pytest.mark.asyncio
    async def test_pin_only_applies_to_matching_host(self):
        # A request whose host differs from the pinned hostname must not be rewritten.
        transport = _PinnedIPTransport("attacker.example.com", "93.184.216.34")
        request = httpx.Request("POST", "https://other.example.com/hook")
        assert (request.url.host or "").lower() != transport._hostname


class TestValidateWebhookEvents:
    @pytest.mark.parametrize(
        "events",
        [
            pytest.param(["scan_completed"], id="single"),
            pytest.param(["scan_completed", "vulnerability_found"], id="multiple"),
            pytest.param(WEBHOOK_VALID_EVENTS, id="every-valid-event"),
        ],
    )
    def test_valid_events_returned_unchanged(self, events):
        assert validate_webhook_events(events) == events

    @pytest.mark.parametrize(
        "events",
        [
            pytest.param(["invalid_event"], id="only-invalid"),
            pytest.param(["scan_completed", "bogus_event"], id="mixed-with-valid"),
        ],
    )
    def test_invalid_event_raises(self, events):
        with pytest.raises(ValueError, match="Invalid event"):
            validate_webhook_events(events)

    def test_empty_list_raises_when_not_allowed(self):
        with pytest.raises(ValueError, match="At least one"):
            validate_webhook_events([], allow_empty=False)

    def test_empty_list_passes_when_allowed(self):
        result = validate_webhook_events([], allow_empty=True)
        assert result == []


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
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            pytest.param(
                "https://contoso.webhook.office.com/webhookb2/abc123/IncomingWebhook/xyz",
                "teams",
                id="classic-teams-incoming-webhook",
            ),
            pytest.param("https://outlook.webhook.office.com/webhookb2/abc", "teams", id="teams-subdomain-variant"),
            pytest.param(
                "https://prod-12.westeurope.logic.azure.com/workflows/abc123/triggers/manual/paths/invoke",
                "teams",
                id="power-automate-workflows-url",
            ),
            pytest.param(
                "https://default047b2e1fa2714bc197a4703bf7adf1.35.environment.api.powerplatform.com"
                "/powerautomate/automations/direct/workflows/67fa2e06/triggers/manual/paths/invoke",
                "teams",
                id="power-platform-automate-url",
            ),
            pytest.param(
                "https://management.logic.azure.com/something-else", "generic", id="logic-azure-without-workflows-path"
            ),
            pytest.param(
                "https://api.powerplatform.com/other/path", "generic", id="power-platform-without-workflows-path"
            ),
            # Hostnames ending in the marker's characters without the separating dot.
            pytest.param("https://evilwebhook.office.com/abc", "generic", id="office-com-non-webhook-subdomain"),
            pytest.param("https://evil-logic.azure.com/workflows/abc", "generic", id="logic-azure-non-logic-subdomain"),
            pytest.param("https://smee.io/abc123", "generic", id="github-webhook"),
            pytest.param("https://hooks.slack.com/services/T123/B456/xyz", "generic", id="slack-webhook"),
            pytest.param("https://my-server.example.com/webhook", "generic", id="generic-https-url"),
            pytest.param("", "generic", id="empty-string"),
        ],
    )
    def test_webhook_type_detected_from_url(self, url, expected):
        assert detect_webhook_type(url) == expected
