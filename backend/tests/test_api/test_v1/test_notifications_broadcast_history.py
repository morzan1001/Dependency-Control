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


def test_the_history_names_creators_and_teams_and_keeps_the_ids_it_cannot_resolve():
    from datetime import datetime, timezone

    from app.api.v1.endpoints.notifications import get_broadcast_history

    db = FakeDatabase()
    sent = [datetime(2026, 9, day, tzinfo=timezone.utc) for day in (1, 2, 3)]
    broadcasts = [
        {"_id": "b-teams", "created_by": "u-ada", "teams": ["t-alpha", "t-gone"], "created_at": sent[2]},
        {"_id": "b-gone", "created_by": "u-deleted", "teams": [], "created_at": sent[1]},
        {"_id": "b-global", "created_by": "u-ada", "teams": None, "created_at": sent[0]},
    ]

    async def _run():
        await db.users.insert_one({"_id": "u-ada", "username": "ada", "email": "ada@test.com"})
        await db.teams.insert_one({"_id": "t-alpha", "name": "Alpha", "members": []})
        for broadcast in broadcasts:
            await db.broadcasts.insert_one(
                {**broadcast, "type": "general", "target_type": "teams", "subject": "s", "message": "m"}
            )
        return await get_broadcast_history(db=db, current_user=User(id="admin", username="admin", email="a@t.com"))

    history = [item.model_dump() for item in asyncio.run(_run())]

    assert [(item["id"], item["created_by"], item["teams"]) for item in history] == [
        ("b-teams", "ada", ["Alpha", "t-gone"]),
        ("b-gone", "u-deleted", None),
        ("b-global", "ada", None),
    ]
    assert [item["created_at"] for item in history] == [at.isoformat() for at in reversed(sent)]
