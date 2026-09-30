"""The broadcast history badge follows the audience the message was actually sent to."""

import asyncio
from typing import Any

import pytest
from fastapi import BackgroundTasks

from app.api.v1.endpoints.notifications import broadcast_message
from app.models.user import User
from app.schemas.notification import BroadcastRequest
from tests.mocks.fake_mongo import FakeDatabase


def _send(body: dict[str, Any]) -> list[dict[str, Any]]:
    db = FakeDatabase()
    user = User(id="broadcaster-1", username="broadcaster", email="broadcaster@test.com", permissions=[])
    payload = BroadcastRequest.model_validate({"subject": "s", "message": "m", "channels": ["email"], **body})

    async def _run() -> list[dict[str, Any]]:
        await broadcast_message(payload=payload, background_tasks=BackgroundTasks(), db=db, current_user=user)
        history: list[dict[str, Any]] = await db.broadcasts.find({}).to_list(None)
        return history

    return asyncio.run(_run())


@pytest.mark.parametrize(
    "body",
    [
        {"type": "advisory", "target_type": "global"},
        {"type": "advisory", "target_type": "teams", "target_teams": ["t1"]},
    ],
)
def test_a_global_or_team_announcement_is_recorded_as_general_whatever_type_the_client_sends(body):
    [entry] = _send(body)

    assert entry["type"] == "general"
