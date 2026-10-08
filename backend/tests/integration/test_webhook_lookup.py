"""Webhook selection and the circuit breaker on a real server, which decides null-versus-missing and $or nesting."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.webhook import Webhook
from app.services.webhooks.webhook_service import WebhookService

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_EVENT = "scan.completed"


async def _hook(db, hook_id: str, **fields) -> None:
    doc = {"_id": hook_id, "url": f"https://example.com/{hook_id}", "project_id": None, "team_id": None}
    await db.webhooks.insert_one({**doc, "events": [_EVENT], "is_active": True, **fields})


async def test_one_lookup_selects_the_project_its_teams_and_the_global_hooks(db):
    now = datetime.now(timezone.utc)
    await _hook(db, "global")
    await db.webhooks.insert_one(
        {"_id": "global-without-scope-fields", "url": "https://example.com/g", "events": [_EVENT], "is_active": True}
    )
    await _hook(db, "project", project_id="p1")
    await _hook(db, "alpha", team_id="alpha")
    await _hook(db, "recovered", team_id="alpha", circuit_breaker_until=now - timedelta(minutes=1))
    await _hook(db, "other-project", project_id="p2")
    await _hook(db, "other-team", team_id="zulu")
    await _hook(db, "switched-off", is_active=False)
    await _hook(db, "cooling-down", circuit_breaker_until=now + timedelta(hours=1))
    await _hook(db, "other-event", events=["analysis.failed"])

    hooks = await WebhookService()._get_webhooks_for_event(db, "p1", _EVENT, team_ids=["alpha"])

    assert {hook.id for hook in hooks} == {"global", "global-without-scope-fields", "project", "alpha", "recovered"}


async def test_the_fifth_consecutive_failure_opens_the_circuit_once_and_a_success_closes_it(db):
    await _hook(db, "flaky")
    flaky = Webhook(**await db.webhooks.find_one({"_id": "flaky"}))
    service = WebhookService()

    for _ in range(4):
        await service._update_webhook_status(db, flaky, success=False)
    still_closed = await db.webhooks.find_one({"_id": "flaky"})
    await service._update_webhook_status(db, flaky, success=False)
    opened = await db.webhooks.find_one({"_id": "flaky"})
    await service._update_webhook_status(db, flaky, success=False)
    kept = await db.webhooks.find_one({"_id": "flaky"})
    await service._update_webhook_status(db, flaky, success=True)
    closed = await db.webhooks.find_one({"_id": "flaky"})

    assert still_closed.get("circuit_breaker_until") is None
    assert opened["circuit_breaker_until"] > datetime.now(timezone.utc)
    assert kept["circuit_breaker_until"] == opened["circuit_breaker_until"]
    assert (closed["consecutive_failures"], closed["circuit_breaker_until"]) == (0, None)
    assert (closed["total_failures"], closed["total_deliveries"]) == (6, 1)


async def test_deliveries_sent_before_an_update_leave_the_state_of_the_new_settings_alone(
    db, client, admin_auth_headers
):
    await _hook(db, "rotated")
    service = WebhookService()
    [stale] = await service._get_webhooks_for_event(db, None, _EVENT)

    updated = await client.patch(
        "/api/v1/webhooks/rotated", json={"url": "https://example.com/fixed"}, headers=admin_auth_headers
    )
    for _ in range(5):
        await service._update_webhook_status(db, stale, success=False)
    await service._update_webhook_status(db, stale, success=True)
    doc = await db.webhooks.find_one({"_id": "rotated"})
    await service._update_webhook_status(db, Webhook(**doc), success=False)
    current = await db.webhooks.find_one({"_id": "rotated"})

    assert updated.status_code == 200
    state = ("consecutive_failures", "circuit_breaker_until", "last_failure_at", "last_triggered_at")
    assert [doc[field] for field in state] == [0, None, None, None]
    assert [hook.id for hook in await service._get_webhooks_for_event(db, None, _EVENT)] == ["rotated"]
    assert current["consecutive_failures"] == 1
