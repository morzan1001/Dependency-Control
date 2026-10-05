"""Reading a PQC migration plan reaches no webhook subscriber and no project member."""

from unittest.mock import AsyncMock

import pytest

from app.core.constants import NOTIFICATION_EVENTS, WEBHOOK_VALID_EVENTS
from app.services.analytics.cache import get_analytics_cache
from app.services.notifications.service import notification_service
from app.services.webhooks import webhook_service

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]


@pytest.fixture(autouse=True)
def _cold_plan_cache():
    get_analytics_cache().clear()
    yield
    get_analytics_cache().clear()


async def test_reading_a_project_plan_delivers_no_webhook_and_no_notification(
    client, db, owner_auth_headers_proj, monkeypatch
):
    await db.webhooks.insert_one(
        {
            "_id": "pqc-subscriber",
            "url": "https://example.com/hook",
            "project_id": "p",
            "team_id": None,
            "events": WEBHOOK_VALID_EVENTS,
            "is_active": True,
        }
    )
    await db.users.insert_one(
        {
            "_id": "ownerp",
            "username": "ownerp",
            "email": "ownerp@example.com",
            "is_active": True,
            "hashed_password": "x",
            "notification_preferences": {event: ["email"] for event in NOTIFICATION_EVENTS},
        }
    )
    post = AsyncMock(return_value=(200, None, None))
    send = AsyncMock()
    monkeypatch.setattr(webhook_service, "_post_bounded", post)
    monkeypatch.setattr(notification_service.email_provider, "send", send)

    resp = await client.get(
        "/api/v1/analytics/crypto/pqc-migration?scope=project&scope_id=p", headers=owner_auth_headers_proj
    )

    assert resp.status_code == 200, resp.text
    assert post.await_count == 0
    assert send.await_count == 0
