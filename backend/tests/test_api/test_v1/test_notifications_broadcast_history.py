"""The broadcast history badge follows the audience the message was actually sent to."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import BackgroundTasks

from app.api.v1.endpoints.notifications import broadcast_message
from app.models.user import User
from app.schemas.notification import BroadcastRequest
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.notifications"


def _send(body: dict[str, Any], handler: str) -> list[dict[str, Any]]:
    db = FakeDatabase()
    user = User(id="broadcaster-1", username="broadcaster", email="broadcaster@test.com", permissions=[])
    payload = BroadcastRequest.model_validate({"subject": "s", "message": "m", **body})

    async def _run() -> list[dict[str, Any]]:
        with patch(f"{MODULE}.{handler}", AsyncMock(return_value=(3, 0))):
            await broadcast_message(payload=payload, background_tasks=BackgroundTasks(), db=db, current_user=user)
        history: list[dict[str, Any]] = await db.broadcasts.find({}).to_list(None)
        return history

    return asyncio.run(_run())


@pytest.mark.parametrize(
    ("body", "handler"),
    [
        ({"type": "advisory", "target_type": "global"}, "_handle_global_broadcast"),
        ({"type": "advisory", "target_type": "teams", "target_teams": ["t1"]}, "_handle_teams_broadcast"),
    ],
)
def test_a_global_or_team_announcement_is_recorded_as_general_whatever_type_the_client_sends(body, handler):
    [entry] = _send(body, handler)

    assert entry["type"] == "general"
