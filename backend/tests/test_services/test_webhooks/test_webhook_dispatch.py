"""Which subscriptions a fired event actually reaches, and what counts as delivered.

A subscription that was switched off, or one still inside its circuit-breaker cool-down, must not
be dialled; and a rejected POST must not be filed away as a success, because the delivery log and
the consecutive-failure counter are the only places an operator can see that a hook is broken.
"""

from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.mocks.fake_mongo import FakeDatabase

ws_module = importlib.import_module("app.services.webhooks.webhook_service")

_EVENT = "scan.completed"


async def _seed_hook(db: FakeDatabase, hook_id: str, **overrides) -> None:
    doc = {
        "_id": hook_id,
        "url": f"https://example.com/{hook_id}",
        "project_id": None,
        "team_id": None,
        "events": [_EVENT],
        "is_active": True,
    }
    doc.update(overrides)
    await db.webhooks.insert_one(doc)


async def _selected(db: FakeDatabase) -> set[str]:
    hooks = await ws_module.WebhookService()._get_webhooks_for_event(db, None, _EVENT)
    return {hook.id for hook in hooks}


class TestWebhookSelection:
    @pytest.mark.asyncio
    async def test_a_deactivated_subscription_is_not_dispatched_to(self):
        db = FakeDatabase()
        await _seed_hook(db, "live")
        await _seed_hook(db, "switched-off", is_active=False)

        assert await _selected(db) == {"live"}

    @pytest.mark.asyncio
    async def test_a_subscription_inside_its_cool_down_is_not_dispatched_to(self):
        db = FakeDatabase()
        now = datetime.now(timezone.utc)
        await _seed_hook(db, "healthy")
        await _seed_hook(db, "cooling-down", circuit_breaker_until=now + timedelta(hours=1))

        assert await _selected(db) == {"healthy"}

    @pytest.mark.asyncio
    async def test_a_subscription_whose_cool_down_expired_is_dispatched_to_again(self):
        db = FakeDatabase()
        now = datetime.now(timezone.utc)
        await _seed_hook(db, "recovered", circuit_breaker_until=now - timedelta(minutes=1))

        assert await _selected(db) == {"recovered"}

    @pytest.mark.asyncio
    async def test_a_subscription_that_never_tripped_the_breaker_is_dispatched_to(self):
        db = FakeDatabase()
        await _seed_hook(db, "never-tripped", circuit_breaker_until=None)
        await _seed_hook(db, "no-breaker-field-at-all")
        db.webhooks._docs["no-breaker-field-at-all"].pop("circuit_breaker_until", None)

        assert await _selected(db) == {"never-tripped", "no-breaker-field-at-all"}


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code
        self.text = ""


def _client_returning(status_code: int):
    class _FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, *args, **kwargs):
            return _FakeResponse(status_code)

    return _FakeClient


async def _deliver(status_code: int) -> tuple[bool, AsyncMock, AsyncMock]:
    service = ws_module.WebhookService(timeout=1.0, max_retries=1)
    webhook = SimpleNamespace(id="wh-1", url="https://example.com/hook", webhook_type="generic", secret=None)
    status = AsyncMock()
    log = AsyncMock()

    with (
        patch.object(ws_module, "InstrumentedAsyncClient", _client_returning(status_code)),
        patch.object(ws_module, "build_pinned_transport", new=AsyncMock(return_value=None)),
        patch.object(service, "_format_payload", return_value={"ok": True}),
        patch.object(service, "_build_headers", return_value={}),
        patch.object(service, "_update_webhook_status", new=status),
        patch.object(service, "_log_webhook_delivery", new=log),
    ):
        delivered = await service._send_webhook(db=MagicMock(), webhook=webhook, payload={}, event_type=_EVENT)

    return delivered, status, log


class TestDeliveryOutcome:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [400, 403, 404, 429])
    async def test_a_rejected_post_is_recorded_as_a_failure(self, status_code: int):
        delivered, status, log = await _deliver(status_code)

        assert delivered is False
        assert status.await_args.kwargs["success"] is False
        assert log.await_args.kwargs["success"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [200, 202, 204])
    async def test_an_accepted_post_is_recorded_as_a_delivery(self, status_code: int):
        delivered, status, log = await _deliver(status_code)

        assert delivered is True
        assert status.await_args.kwargs["success"] is True
        assert log.await_args.kwargs["success"] is True
