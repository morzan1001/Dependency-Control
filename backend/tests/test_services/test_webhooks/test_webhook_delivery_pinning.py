"""The real webhook delivery path must connect through the DNS-rebinding-safe pinned transport."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import importlib

from app.services.webhooks.validation import _PinnedIPTransport

# The package binds ``webhook_service`` to a singleton instance, shadowing the submodule;
# import the real module via importlib so the WebhookService and patch target resolve.
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
