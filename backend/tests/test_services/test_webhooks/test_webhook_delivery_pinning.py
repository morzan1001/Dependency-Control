"""The real webhook delivery path must connect through the DNS-rebinding-safe pinned transport."""

import asyncio
import importlib
import logging
import socket
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.config import settings
from app.services.webhooks.validation import _PinnedIPTransport

# The package binds ``webhook_service`` to a singleton instance, shadowing the submodule;
# import the real module via importlib so the WebhookService and patch target resolve.
ws_module = importlib.import_module("app.services.webhooks.webhook_service")


def _capturing_client(captured: dict):
    class _FakeClient:
        def __init__(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        @asynccontextmanager
        async def stream(self, *args, **kwargs):
            yield SimpleNamespace(status_code=200)

    return _FakeClient


def _service(attempts: int = 3):
    with patch.object(settings, "WEBHOOK_MAX_RETRIES", attempts):
        return ws_module.WebhookService(timeout=1.0)


def _resolving(*answers):
    """Resolver stand-in answering each call with the next entry; an exception entry is raised."""
    pending = list(answers)

    async def getaddrinfo(host, port, type=None):
        answer = pending.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return [(0, 0, 0, "", (answer, 0))]

    return patch.object(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)


def _webhook():
    return SimpleNamespace(
        id="wh-1",
        url="https://attacker.example.com/hook",
        webhook_type="generic",
        secret="s3cret",
        headers=None,
    )


@pytest.mark.asyncio
async def test_send_webhook_connects_through_pinned_transport():
    captured: dict = {}
    service = ws_module.WebhookService(timeout=1.0, max_attempts=1)
    webhook = _webhook()

    with (
        patch.object(ws_module, "InstrumentedAsyncClient", _capturing_client(captured)),
        _resolving("93.184.216.34"),
        patch.object(service, "_format_payload", return_value={"ok": True}),
        patch.object(service, "_build_headers", return_value={}),
        patch.object(service, "_update_webhook_status", new=AsyncMock()),
        patch.object(service, "_log_webhook_delivery", new=AsyncMock()),
    ):
        await service._send_webhook(
            db=MagicMock(),
            webhook=webhook,
            payload={},
            event_type="scan.completed",
        )

    transport = captured.get("kwargs", {}).get("transport")
    assert isinstance(transport, _PinnedIPTransport), (
        "WebhookService._send_webhook must deliver through build_pinned_transport()'s "
        f"pinned transport to defeat DNS rebinding; got transport={transport!r}. The SSRF fix "
        "(finding #1) is still unwired in webhook_service.py."
    )


@pytest.mark.asyncio
async def test_test_webhook_connects_through_pinned_transport():
    captured: dict = {}
    service = ws_module.WebhookService(timeout=1.0, max_attempts=1)
    webhook = _webhook()

    with (
        patch.object(ws_module, "InstrumentedAsyncClient", _capturing_client(captured)),
        _resolving("93.184.216.34"),
        patch.object(service, "_format_payload", return_value={"ok": True}),
        patch.object(service, "_build_headers", return_value={}),
    ):
        await service.test_webhook(webhook)

    transport = captured.get("kwargs", {}).get("transport")
    assert isinstance(transport, _PinnedIPTransport), (
        "WebhookService.test_webhook must deliver through build_pinned_transport()'s "
        f"pinned transport to defeat DNS rebinding; got transport={transport!r}. The SSRF fix "
        "(finding #1) is still unwired in webhook_service.py."
    )


@pytest.mark.asyncio
async def test_a_dns_hiccup_is_retried():
    service = _service(attempts=2)
    log = AsyncMock()
    with (
        _resolving(socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution"), "93.184.216.34"),
        patch.object(httpx.AsyncHTTPTransport, "handle_async_request", new=AsyncMock(return_value=httpx.Response(204))),
        patch.object(ws_module.asyncio, "sleep", new=AsyncMock()),
        patch.object(service, "_update_webhook_status", new=AsyncMock()),
        patch.object(service, "_log_webhook_delivery", new=log),
    ):
        delivered = await service._send_webhook(
            db=MagicMock(), webhook=_webhook(), payload={}, event_type="scan.completed"
        )

    assert delivered is True
    assert log.await_args.kwargs["retry_count"] == 1


_INTERNAL = SimpleNamespace(
    id="wh-1", url="https://vault.internal.example/hook", webhook_type="generic", secret=None, headers=None
)


@pytest.mark.asyncio
async def test_the_test_button_refuses_an_internal_name_without_revealing_its_address(caplog):
    with caplog.at_level(logging.WARNING), _resolving("10.20.30.40"):
        result = await _service().test_webhook(_INTERNAL)

    assert result == {
        "success": False,
        "status_code": None,
        "error": "Target is not an allowed webhook destination",
        "response_time_ms": None,
    }
    assert "10.20.30.40" in caplog.text


@pytest.mark.asyncio
async def test_delivery_to_an_internal_name_is_refused_once_without_revealing_its_address():
    service = _service()
    log = AsyncMock()
    with (
        _resolving("10.20.30.40", "10.20.30.40", "10.20.30.40"),
        patch.object(ws_module.asyncio, "sleep", new=AsyncMock()),
        patch.object(service, "_update_webhook_status", new=AsyncMock()),
        patch.object(service, "_log_webhook_delivery", new=log),
    ):
        delivered = await service._send_webhook(
            db=MagicMock(), webhook=_INTERNAL, payload={}, event_type="scan.completed"
        )

    assert delivered is False
    assert (log.await_args.kwargs["error"], log.await_args.kwargs["retry_count"]) == (
        "Target is not an allowed webhook destination",
        0,
    )


@pytest.mark.asyncio
async def test_connecting_has_its_own_short_timeout():
    captured: dict = {}
    with patch.object(ws_module, "InstrumentedAsyncClient", _capturing_client(captured)), _resolving("93.184.216.34"):
        await _service().test_webhook(_webhook())

    assert captured["kwargs"]["timeout"] == httpx.Timeout(1.0, connect=5.0)
