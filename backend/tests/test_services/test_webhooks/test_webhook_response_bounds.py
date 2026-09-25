"""A webhook receiver controls the response, so delivery and the test button must bound both its size and its duration."""

from __future__ import annotations

import asyncio
import importlib
import time
from collections.abc import AsyncIterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.constants import WEBHOOK_RESPONSE_BODY_LIMIT_BYTES

ws_module = importlib.import_module("app.services.webhooks.webhook_service")

_CHUNK = 64 * 1024
_HUGE_BODY_BYTES = 256 * WEBHOOK_RESPONSE_BODY_LIMIT_BYTES
_DEADLINE = 0.3
# Guards the test run itself: an unbounded implementation must fail here instead of hanging.
_TEST_GUARD = 5.0


class _Body:
    """Response body that counts how many bytes the client actually pulled."""

    def __init__(self, total_bytes: int | None, chunk: bytes, pause: float = 0.0) -> None:
        self.pulled = 0
        self._total = total_bytes
        self._chunk = chunk
        self._pause = pause

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while self._total is None or self.pulled < self._total:
            self.pulled += len(self._chunk)
            yield self._chunk
            await asyncio.sleep(self._pause)


def _transport(status_code: int, body: _Body) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status_code, content=body))


def _webhook() -> SimpleNamespace:
    return SimpleNamespace(id="wh-1", url="https://example.com/hook", webhook_type="generic", secret=None, headers=None)


async def _deliver(transport: httpx.MockTransport) -> tuple[bool, AsyncMock, float]:
    service = ws_module.WebhookService(timeout=_DEADLINE, max_retries=1)
    log = AsyncMock()
    with (
        patch.object(ws_module, "build_pinned_transport", new=AsyncMock(return_value=transport)),
        patch.object(service, "_update_webhook_status", new=AsyncMock()),
        patch.object(service, "_log_webhook_delivery", new=log),
    ):
        started = time.monotonic()
        async with asyncio.timeout(_TEST_GUARD):
            delivered = await service._send_webhook(
                db=MagicMock(), webhook=_webhook(), payload={}, event_type="scan.completed"
            )
    return delivered, log, time.monotonic() - started


async def _test_button(transport: httpx.MockTransport) -> dict:
    service = ws_module.WebhookService(timeout=_DEADLINE, max_retries=1)
    with patch.object(ws_module, "build_pinned_transport", new=AsyncMock(return_value=transport)):
        async with asyncio.timeout(_TEST_GUARD):
            return await service.test_webhook(_webhook())


class TestHugeBody:
    @pytest.mark.asyncio
    async def test_delivery_reads_at_most_the_cap_and_records_the_failure(self):
        body = _Body(_HUGE_BODY_BYTES, b"x" * _CHUNK)

        delivered, log, _ = await _deliver(_transport(500, body))

        assert delivered is False
        assert log.await_args.kwargs["error"] == "HTTP 500: " + "x" * 200
        assert body.pulled <= WEBHOOK_RESPONSE_BODY_LIMIT_BYTES

    @pytest.mark.asyncio
    async def test_test_button_reads_at_most_the_cap(self):
        body = _Body(_HUGE_BODY_BYTES, b"x" * _CHUNK)

        result = await _test_button(_transport(500, body))

        assert (result["success"], result["status_code"]) == (False, 500)
        assert result["error"] == "HTTP 500: " + "x" * 200
        assert body.pulled <= WEBHOOK_RESPONSE_BODY_LIMIT_BYTES

    @pytest.mark.asyncio
    async def test_an_accepted_delivery_does_not_read_the_body(self):
        body = _Body(_HUGE_BODY_BYTES, b"x" * _CHUNK)

        delivered, log, _ = await _deliver(_transport(200, body))

        assert delivered is True
        assert log.await_args.kwargs["success"] is True
        assert body.pulled == 0


class TestSlowDrip:
    @pytest.mark.asyncio
    async def test_delivery_hits_the_deadline_and_is_recorded_as_failed(self):
        body = _Body(None, b"x", pause=0.05)

        delivered, log, elapsed = await _deliver(_transport(500, body))

        assert delivered is False
        assert log.await_args.kwargs["success"] is False
        assert log.await_args.kwargs["error"] == "Timeout"
        assert elapsed < _DEADLINE + 1.0

    @pytest.mark.asyncio
    async def test_test_button_hits_the_deadline(self):
        body = _Body(None, b"x", pause=0.05)

        result = await _test_button(_transport(500, body))

        assert result == {
            "success": False,
            "status_code": None,
            "error": f"Request timed out after {_DEADLINE}s",
            "response_time_ms": None,
        }


@pytest.mark.asyncio
async def test_delivery_asks_for_an_uncompressed_answer():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    delivered, _, _ = await _deliver(httpx.MockTransport(handler))

    assert delivered is True
    assert seen[0].headers["accept-encoding"] == "identity"
