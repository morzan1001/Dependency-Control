"""The PQC migration-plan endpoint fires the pqc_migration_plan.generated webhook after returning the plan."""

from unittest.mock import AsyncMock

import pytest

from app.core.constants import (
    NOTIFICATION_EVENT_PQC_MIGRATION_PLAN_GENERATED,
    WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED,
)
from app.services.analytics.cache import get_analytics_cache


@pytest.fixture(autouse=True)
def _clear_analytics_cache():
    get_analytics_cache().clear()
    yield
    get_analytics_cache().clear()


@pytest.mark.asyncio
async def test_pqc_migration_fires_webhook(
    client,
    db,
    owner_auth_headers_proj,
    monkeypatch,
):
    from app.services.webhooks import webhook_service

    trigger_mock = AsyncMock()
    monkeypatch.setattr(webhook_service, "trigger_webhooks", trigger_mock)

    resp = await client.get(
        "/api/v1/analytics/crypto/pqc-migration?scope=project&scope_id=p",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text

    trigger_mock.assert_awaited()
    call = trigger_mock.await_args
    assert call.kwargs.get("event_type") == WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED
    payload = call.kwargs.get("payload")
    assert payload is not None
    assert payload["event"] == WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED
    assert payload["scope"] == "project"
    assert payload["scope_id"] == "p"
    assert "total_items" in payload
    assert "status_counts" in payload
    assert "mappings_version" in payload
    # project_id restricts webhook delivery to the scoped project.
    assert call.kwargs.get("project_id") == "p"


@pytest.mark.asyncio
async def test_pqc_webhook_failure_does_not_fail_request(
    client,
    db,
    owner_auth_headers_proj,
    monkeypatch,
):
    from app.services.webhooks import webhook_service

    monkeypatch.setattr(
        webhook_service,
        "trigger_webhooks",
        AsyncMock(side_effect=RuntimeError("boom")),
    )

    resp = await client.get(
        "/api/v1/analytics/crypto/pqc-migration?scope=user",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_a_team_plan_carries_no_project_id_into_the_dispatch(
    client,
    db,
    owner_auth_headers_proj,
    monkeypatch,
):
    """project_id selects the project- and team-scoped subscribers; a team id in that slot is
    read as a project id and resolves against the wrong collection."""
    from app.services.webhooks import webhook_service

    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": "ownerp", "role": "admin"}]})
    trigger_mock = AsyncMock()
    monkeypatch.setattr(webhook_service, "trigger_webhooks", trigger_mock)

    resp = await client.get(
        "/api/v1/analytics/crypto/pqc-migration?scope=team&scope_id=t1",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text

    trigger_mock.assert_awaited()
    call = trigger_mock.await_args
    assert call.kwargs.get("payload")["scope_id"] == "t1"
    assert call.kwargs.get("project_id") is None


@pytest.mark.asyncio
async def test_a_project_plan_reaches_the_members_subscribed_to_the_event(
    client,
    db,
    owner_auth_headers_proj,
    monkeypatch,
):
    """Delivery is matched on the event name a member subscribed to, so a literal drifting from
    NOTIFICATION_EVENT_PQC_MIGRATION_PLAN_GENERATED silently stops it."""
    from app.services.notifications.service import notification_service

    await db.users.update_one(
        {"_id": "ownerp"},
        {
            "$set": {
                "username": "ownerp",
                "email": "ownerp@example.com",
                "is_active": True,
                "hashed_password": "x",
                "notification_preferences": {NOTIFICATION_EVENT_PQC_MIGRATION_PLAN_GENERATED: ["email"]},
            }
        },
        upsert=True,
    )
    send = AsyncMock()
    monkeypatch.setattr(notification_service.email_provider, "send", send)

    resp = await client.get(
        "/api/v1/analytics/crypto/pqc-migration?scope=project&scope_id=p",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text

    send.assert_awaited_once()
    assert send.await_args.args[0] == "ownerp@example.com"
