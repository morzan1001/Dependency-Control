"""Verify the PQC migration-plan endpoint fires the
`pqc_migration_plan.generated` webhook after returning the plan."""

from unittest.mock import AsyncMock

import pytest

from app.core.constants import WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED
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
    # Project-scoped call must pass project_id to restrict webhook delivery.
    assert call.kwargs.get("project_id") == "p"


@pytest.mark.asyncio
async def test_pqc_webhook_failure_does_not_fail_request(
    client,
    db,
    owner_auth_headers_proj,
    monkeypatch,
):
    """A misbehaving webhook must never surface to the caller."""
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
