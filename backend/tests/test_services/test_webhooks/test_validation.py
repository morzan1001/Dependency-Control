"""Tests for webhook URL and event validation."""

import asyncio
import socket
from unittest.mock import patch

import httpx
import pytest

from app.core.constants import WEBHOOK_VALID_EVENTS
from app.core.http_utils import InstrumentedAsyncClient
from app.schemas.webhook import (
    detect_webhook_type,
    validate_webhook_event_type,
    validate_webhook_events,
    validate_webhook_url,
)
from app.services.webhooks.validation import (
    WebhookTargetBlocked,
    _PinnedIPTransport,
    _resolve_and_vet,
    build_pinned_transport,
)


def _resolving(*sockaddrs, seen: list[str] | None = None):
    """Stand in for the running loop's resolver; must be entered inside the test's event loop."""

    async def getaddrinfo(host, port, type=None):
        if seen is not None:
            seen.append(host)
        return [(0, 0, 0, "", sockaddr) for sockaddr in sockaddrs]

    return patch.object(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)


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
        with pytest.raises(ValueError, match=r"private|reserved|link-local"):
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
        with pytest.raises(ValueError, match=r"private|reserved|link-local"):
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
        with patch("app.schemas.webhook.settings") as s:
            s.WEBHOOK_ALLOW_LOCALHOST = False
            with pytest.raises(ValueError, match="Localhost"):
                validate_webhook_url("http://localhost:8080/hook")
            with pytest.raises(ValueError, match="Localhost"):
                validate_webhook_url("http://127.0.0.1/hook")


class TestResolveAndVet:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
    async def test_loopback_hosts_are_exempt_from_pinning(self, host):
        assert await _resolve_and_vet(host) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("sockaddr", "host"),
        [
            pytest.param(("10.0.0.5", 0), "attacker.example.com", id="private-ipv4"),
            pytest.param(("169.254.169.254", 0), "metadata-spoof.example.com", id="metadata-ipv4"),
            pytest.param(("4000::1", 0, 0, 0), "attacker.example.com", id="reserved-ipv6"),
        ],
    )
    async def test_a_name_resolving_to_a_blocked_address_is_refused(self, sockaddr, host):
        with _resolving(sockaddr), pytest.raises(WebhookTargetBlocked) as refused:
            await _resolve_and_vet(host)
        assert str(refused.value) == "Target is not an allowed webhook destination"
        assert f"resolves to blocked address {sockaddr[0]}" in refused.value.detail

    @pytest.mark.asyncio
    async def test_returns_vetted_ip_for_hostname(self):
        with _resolving(("93.184.216.34", 0)):
            assert await _resolve_and_vet("example.com") == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_a_public_ip_literal_pins_to_itself(self):
        assert await _resolve_and_vet("93.184.216.34") == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_a_blocked_ip_literal_is_refused(self):
        with pytest.raises(WebhookTargetBlocked):
            await _resolve_and_vet("192.168.1.1")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "sockaddrs",
        [
            pytest.param([("not-an-ip", 0)], id="unparseable"),
            pytest.param([], id="empty"),
        ],
    )
    async def test_resolution_without_a_usable_ip_fails_closed(self, sockaddrs):
        # Returning None would let an unpinned transport reopen the rebinding window.
        with _resolving(*sockaddrs), pytest.raises(WebhookTargetBlocked) as refused:
            await _resolve_and_vet("weird.example.com")
        assert "no usable IP" in refused.value.detail

    @pytest.mark.asyncio
    async def test_a_resolver_failure_is_a_retryable_connect_error(self):
        async def failing(host, port, type=None):
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

        with (
            patch.object(asyncio.get_running_loop(), "getaddrinfo", failing),
            pytest.raises(httpx.ConnectError, match="Could not resolve"),
        ):
            await _resolve_and_vet("flaky.example.com")


class TestBuildPinnedTransport:
    """Delivery is pinned to the single vetted IP so httpx cannot re-resolve to an internal target."""

    @pytest.mark.asyncio
    async def test_hostname_pins_to_vetted_ip(self):
        with _resolving(("93.184.216.34", 0)):
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
        with _resolving(("93.184.216.34", 0)):
            transport = await build_pinned_transport("https://attacker.example.com/hook")

        # A later resolution to the metadata IP is ignored; the pinned target stays the vetted address.
        request = httpx.Request("POST", "https://attacker.example.com/latest/meta-data/")
        transport._pin(request)
        assert request.url.host == "93.184.216.34"
        assert request.url.host != "169.254.169.254"

    @pytest.mark.asyncio
    async def test_a_url_that_breaks_the_stored_url_rules_is_refused(self):
        with pytest.raises(WebhookTargetBlocked) as refused:
            await build_pinned_transport("https://192.168.1.1/hook")
        assert "private, reserved, or link-local" in refused.value.detail

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
    async def test_pinned_and_plain_transports_reuse_the_http_clients_ssl_context(self):
        pinned = await build_pinned_transport("https://93.184.216.34/hook")
        plain = await build_pinned_transport("http://localhost:8080/hook")

        async with InstrumentedAsyncClient("SslShared") as client:
            shared = client._client._transport._pool._ssl_context
        assert pinned._pool._ssl_context is shared
        assert plain._pool._ssl_context is shared

    @pytest.mark.asyncio
    async def test_a_request_for_another_host_is_refused(self):
        transport = _PinnedIPTransport("attacker.example.com", "93.184.216.34")
        with pytest.raises(ValueError, match="not an allowed webhook destination"):
            await transport.handle_async_request(httpx.Request("POST", "https://other.example.com/hook"))


class TestValidateWebhookEvents:
    @pytest.mark.parametrize(
        "events",
        [
            pytest.param(["scan.completed"], id="single"),
            pytest.param(["scan.completed", "vulnerability.found"], id="multiple"),
            pytest.param(WEBHOOK_VALID_EVENTS, id="every-valid-event"),
        ],
    )
    def test_canonical_events_are_returned_unchanged(self, events):
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

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="At least one"):
            validate_webhook_events([])


class TestValidateWebhookEventType:
    def test_a_legacy_event_name_is_canonicalised(self):
        assert validate_webhook_event_type("scan_completed") == "scan.completed"

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
            pytest.param("https://hooks.slack.com/services/T123/B456/xyz", "slack", id="slack-webhook"),
            pytest.param("https://hooks.slack.com.evil.example/services/T1/B1/x", "generic", id="slack-lookalike-host"),
            pytest.param("https://my-server.example.com/webhook", "generic", id="generic-https-url"),
            pytest.param("", "generic", id="empty-string"),
        ],
    )
    def test_webhook_type_detected_from_url(self, url, expected):
        assert detect_webhook_type(url) == expected


async def _sent_through(transport: httpx.AsyncHTTPTransport, url: str) -> httpx.Request:
    sent: list[httpx.Request] = []

    async def capture(self, request):
        sent.append(request)
        return httpx.Response(204)

    with patch.object(httpx.AsyncHTTPTransport, "handle_async_request", capture):
        async with httpx.AsyncClient(transport=transport) as client:
            await client.post(url)
    return sent[0]


class TestIdnHostPinning:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("url", "a_label"),
        [
            pytest.param("https://xn--mnchen-3ya.de/hook", "xn--mnchen-3ya.de", id="punycode"),
            pytest.param(
                "https://xn--mnchen-3ya.attacker.example/hook",
                "xn--mnchen-3ya.attacker.example",
                id="punycode-subdomain",
            ),
            pytest.param("https://XN--MNCHEN-3YA.DE/hook", "xn--mnchen-3ya.de", id="uppercase-punycode"),
            pytest.param("https://münchen.de/hook", "xn--mnchen-3ya.de", id="unicode"),
            pytest.param("https://example.com。evil/hook", "example.com.evil", id="ideographic-full-stop"),
        ],
    )
    async def test_the_request_goes_to_the_vetted_ip_of_the_name_that_was_vetted(self, url, a_label):
        seen: list[str] = []
        with _resolving(("93.184.216.34", 0), seen=seen):
            transport = await build_pinned_transport(url)

        request = await _sent_through(transport, url)

        assert seen == [a_label]
        assert request.url.host == "93.184.216.34"
        assert request.extensions["sni_hostname"] == a_label
        assert request.headers["Host"] == a_label
