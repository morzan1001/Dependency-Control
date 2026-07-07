"""Guard for review issue #3: the *actual* webhook delivery path must connect
through the DNS-rebinding-safe pinned transport, not a default httpx client that
independently re-resolves the hostname at connect time.

``build_pinned_transport`` / ``_PinnedIPTransport`` (in
``app/services/webhooks/validation.py``) are the correct primitive, but the SSRF
finding (#1) is only genuinely closed once they are wired into
``WebhookService._send_webhook`` and ``WebhookService.send_test_webhook`` in
``app/services/webhooks/webhook_service.py`` (the sites that today construct
``InstrumentedAsyncClient("Webhook Delivery"/"Webhook Test", ...)`` with no
``transport=`` argument, so httpx re-resolves the host and an attacker can rebind
to 169.254.169.254 between the vetting call and the connect).

These tests exercise the real delivery methods and assert the client is built
with a ``_PinnedIPTransport``. They FAIL until the wire-in lands, which is
exactly the tripwire the reviewer asked for: the suite can now detect that the
fix is unwired. Editing ``webhook_service.py`` is outside the scope of the
current change set (validation.py + tests only), so the wire-in is a follow-up.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import importlib

from app.services.webhooks.validation import _PinnedIPTransport

# NOTE: ``app.services.webhooks.__init__`` binds the name ``webhook_service`` to a
# singleton *instance*, shadowing the submodule attribute on the package. Import
# the real module object via importlib so ``ws_module.WebhookService`` and the
# ``InstrumentedAsyncClient`` patch target both resolve correctly.
ws_module = importlib.import_module("app.services.webhooks.webhook_service")


class _FakeResponse:
    status_code = 200
    text = ""


def _capturing_client(captured: dict):
    class _FakeClient:
        def __init__(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, *args, **kwargs):
            return _FakeResponse()

    return _FakeClient


async def _fake_getaddrinfo_public(host, port, type=None):
    # Vetting resolves to a safe public IP; a later (attacker) resolution could
    # return a metadata IP, which pinning must prevent from being connected to.
    return [(0, 0, 0, "", ("93.184.216.34", 0))]


def _webhook():
    return SimpleNamespace(
        id="wh-1",
        url="https://attacker.example.com/hook",
        webhook_type="generic",
        secret="s3cret",
    )


@pytest.mark.asyncio
async def test_send_webhook_connects_through_pinned_transport():
    captured: dict = {}
    service = ws_module.WebhookService(timeout=1.0, max_retries=1)
    webhook = _webhook()

    with (
        patch.object(ws_module, "InstrumentedAsyncClient", _capturing_client(captured)),
        patch("asyncio.get_event_loop") as gel,
        patch.object(service, "_format_payload", return_value={"ok": True}),
        patch.object(service, "_build_headers", return_value={}),
        patch.object(service, "_update_webhook_status", new=AsyncMock()),
        patch.object(service, "_log_webhook_delivery", new=AsyncMock()),
    ):
        gel.return_value.getaddrinfo = _fake_getaddrinfo_public
        await service._send_webhook(
            db=MagicMock(),
            webhook=webhook,
            payload={},
            event_type="scan.completed",
        )

    transport = captured.get("kwargs", {}).get("transport")
    assert isinstance(transport, _PinnedIPTransport), (
        "WebhookService._send_webhook must deliver through build_pinned_transport()'s "
        "pinned transport to defeat DNS rebinding; got transport=%r. The SSRF fix "
        "(finding #1) is still unwired in webhook_service.py." % (transport,)
    )


@pytest.mark.asyncio
async def test_test_webhook_connects_through_pinned_transport():
    captured: dict = {}
    service = ws_module.WebhookService(timeout=1.0, max_retries=1)
    webhook = _webhook()

    with (
        patch.object(ws_module, "InstrumentedAsyncClient", _capturing_client(captured)),
        patch("asyncio.get_event_loop") as gel,
        patch.object(service, "_format_payload", return_value={"ok": True}),
        patch.object(service, "_build_headers", return_value={}),
    ):
        gel.return_value.getaddrinfo = _fake_getaddrinfo_public
        await service.test_webhook(webhook)

    transport = captured.get("kwargs", {}).get("transport")
    assert isinstance(transport, _PinnedIPTransport), (
        "WebhookService.test_webhook must deliver through build_pinned_transport()'s "
        "pinned transport to defeat DNS rebinding; got transport=%r. The SSRF fix "
        "(finding #1) is still unwired in webhook_service.py." % (transport,)
    )
