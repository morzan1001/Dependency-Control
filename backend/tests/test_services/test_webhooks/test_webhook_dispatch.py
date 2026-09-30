"""Which subscriptions a fired event actually reaches, and what counts as delivered.

A subscription that was switched off, or one still inside its circuit-breaker cool-down, must not
be dialled; and a rejected POST must not be filed away as a success, because the delivery log and
the consecutive-failure counter are the only places an operator can see that a hook is broken.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.config import settings
from app.core.constants import WEBHOOK_USER_AGENT_VALUE
from app.core.metrics import webhooks_failed_total
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

    @pytest.mark.asyncio
    async def test_a_subscription_stored_under_a_snake_case_alias_is_not_matched(self):
        db = FakeDatabase()
        await _seed_hook(db, "canonical")
        await _seed_hook(db, "alias", events=["scan_completed"])

        assert await _selected(db) == {"canonical"}


class TestWebhookScope:
    @pytest.mark.asyncio
    async def test_team_ids_reach_those_teams_hooks_without_a_project(self):
        db = FakeDatabase()
        await _seed_hook(db, "global")
        await _seed_hook(db, "alpha", team_id="alpha")
        await _seed_hook(db, "bravo", team_id="bravo")

        hooks = await ws_module.WebhookService()._get_webhooks_for_event(db, None, _EVENT, team_ids=["alpha"])

        assert {hook.id for hook in hooks} == {"global", "alpha"}

    @pytest.mark.asyncio
    async def test_the_callers_team_ids_replace_the_project_read_and_one_query_serves_every_scope(self):
        db = FakeDatabase()
        await db.projects.insert_one({"_id": "p1", "name": "p1", "team_ids": ["bravo"]})
        await _seed_hook(db, "project", project_id="p1")
        await _seed_hook(db, "alpha", team_id="alpha")
        await _seed_hook(db, "bravo", team_id="bravo")
        await _seed_hook(db, "global")
        find = MagicMock(wraps=db.webhooks.find)
        db.webhooks.find = find

        hooks = await ws_module.WebhookService()._get_webhooks_for_event(db, "p1", _EVENT, team_ids=["alpha"])

        assert {hook.id for hook in hooks} == {"project", "alpha", "global"}
        assert find.call_count == 1

    @pytest.mark.asyncio
    async def test_a_failed_team_lookup_is_counted_and_the_other_scopes_still_fire(self, caplog):
        db = FakeDatabase()
        await _seed_hook(db, "global")
        await _seed_hook(db, "project", project_id="p1")
        db.projects.find_one = AsyncMock(side_effect=RuntimeError("primary stepped down"))
        failed = webhooks_failed_total.labels(event_type=_EVENT)
        before = failed._value.get()

        with caplog.at_level(logging.ERROR, logger=ws_module.__name__):
            hooks = await ws_module.WebhookService()._get_webhooks_for_event(db, "p1", _EVENT)

        assert {hook.id for hook in hooks} == {"global", "project"}
        assert failed._value.get() == before + 1
        assert [r.levelno for r in caplog.records] == [logging.ERROR]


async def _streamed(body: bytes) -> AsyncIterator[bytes]:
    # MockTransport pre-reads bytes content; a real receiver's answer arrives as a stream.
    yield body


async def _deliver(status_code: int) -> tuple[bool, AsyncMock, AsyncMock]:
    service = ws_module.WebhookService(timeout=1.0, max_attempts=1)
    webhook = SimpleNamespace(id="wh-1", url="https://example.com/hook", webhook_type="generic", secret=None)
    status = AsyncMock()
    log = AsyncMock()

    transport = httpx.MockTransport(lambda request: httpx.Response(status_code, content=_streamed(b"nope")))

    with (
        patch.object(ws_module, "build_pinned_transport", new=AsyncMock(return_value=transport)),
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
        assert log.await_args.kwargs["error"] == f"HTTP {status_code}: nope"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [200, 202, 204])
    async def test_an_accepted_post_is_recorded_as_a_delivery(self, status_code: int):
        delivered, status, log = await _deliver(status_code)

        assert delivered is True
        assert status.await_args.kwargs["success"] is True
        assert log.await_args.kwargs["success"] is True


def _answering(*answers: httpx.Response | Exception) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        answer = answers[len(sent) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer

    return httpx.MockTransport(handler), sent


def _answer(status_code: int, **headers: str) -> httpx.Response:
    return httpx.Response(status_code, headers=headers, content=_streamed(b"nope"))


async def _run(transport: httpx.MockTransport, *, attempts: int = 3, **webhook_fields) -> tuple[bool, dict, list]:
    with patch.object(settings, "WEBHOOK_MAX_RETRIES", attempts):
        service = ws_module.WebhookService(timeout=1.0)
    webhook = SimpleNamespace(
        **{"id": "wh-1", "url": "https://example.com/hook", "webhook_type": "generic", "secret": None, "headers": None}
        | webhook_fields
    )
    log = AsyncMock()
    sleep = AsyncMock()
    with (
        patch.object(ws_module, "build_pinned_transport", new=AsyncMock(return_value=transport)),
        patch.object(service, "_update_webhook_status", new=AsyncMock()),
        patch.object(service, "_log_webhook_delivery", new=log),
        patch.object(ws_module.asyncio, "sleep", new=sleep),
    ):
        delivered = await service._send_webhook(db=MagicMock(), webhook=webhook, payload={}, event_type=_EVENT)
    return delivered, log.await_args.kwargs, [call.args[0] for call in sleep.await_args_list]


class TestRetryPolicy:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [400, 401, 403, 404, 410, 413])
    async def test_a_permanent_rejection_is_sent_once(self, status_code: int):
        transport, sent = _answering(*(_answer(status_code) for _ in range(3)))

        delivered, logged, sleeps = await _run(transport)

        assert (delivered, len(sent), sleeps) == (False, 1, [])
        assert (logged["status_code"], logged["error"], logged["retry_count"]) == (
            status_code,
            f"HTTP {status_code}: nope",
            0,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [408, 500, 503])
    async def test_a_transient_answer_is_retried_with_backoff(self, status_code: int):
        transport, sent = _answering(*(_answer(status_code) for _ in range(3)))

        delivered, logged, sleeps = await _run(transport)

        assert (delivered, len(sent), sleeps) == (False, 3, [1, 2])
        assert (logged["status_code"], logged["retry_count"]) == (status_code, 2)

    @pytest.mark.asyncio
    async def test_a_retry_after_within_the_cap_is_waited_for(self):
        transport, sent = _answering(_answer(429, **{"Retry-After": "7"}), _answer(204))

        delivered, logged, sleeps = await _run(transport)

        assert (delivered, len(sent), sleeps) == (True, 2, [7])
        assert logged["retry_count"] == 1

    @pytest.mark.asyncio
    async def test_a_retry_after_beyond_the_cap_ends_the_delivery(self):
        transport, sent = _answering(*(_answer(429, **{"Retry-After": "3600"}) for _ in range(3)))

        delivered, logged, sleeps = await _run(transport)

        assert (delivered, len(sent), sleeps) == (False, 1, [])
        assert logged["status_code"] == 429

    @pytest.mark.asyncio
    async def test_the_logged_status_and_error_belong_to_the_last_attempt(self):
        transport, _ = _answering(_answer(503), httpx.ConnectTimeout("slow"), httpx.ConnectTimeout("slow"))

        _, logged, _ = await _run(transport)

        assert (logged["status_code"], logged["error"], logged["retry_count"]) == (
            None,
            "Request timed out after 1.0s",
            2,
        )

    @pytest.mark.asyncio
    async def test_zero_configured_retries_still_sends_once(self):
        transport, sent = _answering(_answer(204))

        delivered, logged, _ = await _run(transport, attempts=0)

        assert (delivered, len(sent), logged["retry_count"]) == (True, 1, 0)


class TestDeliveryHeaders:
    @pytest.mark.asyncio
    async def test_every_retry_carries_the_same_delivery_id(self):
        transport, sent = _answering(_answer(503), _answer(204))

        await _run(transport)

        ids = [request.headers["X-Webhook-Delivery"] for request in sent]
        assert ids[0] == ids[1]
        assert len(ids[0]) == 32

    @pytest.mark.asyncio
    async def test_the_v2_signature_covers_the_timestamp_and_the_body(self):
        transport, sent = _answering(_answer(204))

        await _run(transport, secret="s3cret")

        request = sent[0]
        timestamp = request.headers["X-Webhook-Timestamp"]
        signed = hmac.new(b"s3cret", f"{timestamp}.".encode() + request.content, hashlib.sha256).hexdigest()
        assert request.headers["X-Webhook-Signature-V2"] == f"t={timestamp},v1={signed}"
        body_signed = hmac.new(b"s3cret", request.content, hashlib.sha256).hexdigest()
        assert request.headers["X-Webhook-Signature"] == f"sha256={body_signed}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stored_name", ["x-webhook-signature", "content-type", "user-agent"])
    async def test_a_stored_case_variant_cannot_duplicate_a_protocol_header(self, stored_name: str):
        transport, sent = _answering(_answer(204))

        delivered, _, _ = await _run(transport, secret="s3cret", headers={stored_name: "forged", "X-Team": "Müller"})

        request = sent[0]
        expected = {
            "x-webhook-signature": f"sha256={hmac.new(b's3cret', request.content, hashlib.sha256).hexdigest()}",
            "content-type": "application/json",
            "user-agent": WEBHOOK_USER_AGENT_VALUE,
        }[stored_name]
        assert delivered is True
        assert request.headers.get_list(stored_name) == [expected]
        assert (b"X-Team", "Müller".encode("latin-1")) in request.headers.raw

    @pytest.mark.asyncio
    async def test_a_stored_non_latin1_value_fails_once_as_an_invalid_header(self):
        transport, sent = _answering(_answer(204))

        delivered, logged, sleeps = await _run(transport, headers={"X-Team": "€"})

        assert (delivered, len(sent), sleeps) == (False, 0, [])
        assert (logged["status_code"], logged["error"], logged["retry_count"]) == (None, "Invalid header value", 0)
