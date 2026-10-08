"""The chat conversation endpoints answer with the caller's stored conversations and their messages."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.core.permissions import Permissions
from tests.helpers.auth import bearer_headers

_USER = "chat-user"
_CONVERSATION = "conv-legacy"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_legacy_message_is_served_without_its_images_and_token_count(client, db, monkeypatch):
    monkeypatch.setattr(settings, "CHAT_ENABLED", True)
    now = datetime.now(timezone.utc)
    await db["chat_conversations"].insert_one(
        {"_id": _CONVERSATION, "user_id": _USER, "title": "t", "created_at": now, "updated_at": now, "message_count": 1}
    )
    await db["chat_messages"].insert_one(
        {
            "_id": "msg-1",
            "conversation_id": _CONVERSATION,
            "role": "user",
            "content": "what is this?",
            "images": ["aGVsbG8="],
            "tool_calls": [],
            "token_count": 0,
            "created_at": now,
        }
    )

    resp = await client.get(
        f"/api/v1/chat/conversations/{_CONVERSATION}",
        headers=bearer_headers(_USER, [Permissions.CHAT_ACCESS, Permissions.CHAT_HISTORY_READ]),
    )

    assert resp.status_code == 200, resp.text
    (message,) = resp.json()["messages"]
    assert message["content"] == "what is this?"
    assert "images" not in message
    assert "token_count" not in message


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_long_conversation_serves_its_newest_messages_in_order(client, db, monkeypatch):
    monkeypatch.setattr(settings, "CHAT_ENABLED", True)
    t0 = datetime.now(timezone.utc)
    await db["chat_conversations"].insert_one(
        {"_id": _CONVERSATION, "user_id": _USER, "title": "t", "created_at": t0, "updated_at": t0, "message_count": 120}
    )
    await db["chat_messages"].insert_many(
        [
            {
                "_id": f"msg-{i}",
                "conversation_id": _CONVERSATION,
                "role": "user" if i % 2 == 0 else "assistant",
                "content": f"message {i}",
                "tool_calls": [],
                "created_at": t0 + timedelta(seconds=i),
            }
            for i in range(120)
        ]
    )

    resp = await client.get(
        f"/api/v1/chat/conversations/{_CONVERSATION}",
        headers=bearer_headers(_USER, [Permissions.CHAT_ACCESS, Permissions.CHAT_HISTORY_READ]),
    )

    assert resp.status_code == 200, resp.text
    assert [m["content"] for m in resp.json()["messages"]] == [f"message {i}" for i in range(20, 120)]


@pytest.mark.asyncio
async def test_a_conversation_is_created_listed_read_and_deleted_by_its_owner_only(client, db, monkeypatch):
    monkeypatch.setattr(settings, "CHAT_ENABLED", True)
    chat = [Permissions.CHAT_ACCESS, Permissions.CHAT_HISTORY_READ, Permissions.CHAT_HISTORY_DELETE]
    owner, stranger = bearer_headers(_USER, chat), bearer_headers("someone-else", chat)

    created = (await client.post("/api/v1/chat/conversations", json={"title": "Risk talk"}, headers=owner)).json()
    listed = (await client.get("/api/v1/chat/conversations", headers=owner)).json()
    detail = (await client.get(f"/api/v1/chat/conversations/{created['id']}", headers=owner)).json()

    assert set(created) == {"id", "user_id", "title", "created_at", "updated_at", "message_count"}
    assert (created["user_id"], created["title"], created["message_count"]) == (_USER, "Risk talk", 0)
    stored = {key: value for key, value in created.items() if not key.endswith("_at")}
    assert [{key: c[key] for key in stored} for c in listed["conversations"]] == [stored]
    assert listed["total"] == 1
    assert {key: detail["conversation"][key] for key in stored} == stored
    assert detail["messages"] == []
    assert (await client.get("/api/v1/chat/conversations", headers=stranger)).json() == {
        "conversations": [],
        "total": 0,
    }
    assert (await client.get(f"/api/v1/chat/conversations/{created['id']}", headers=stranger)).status_code == 404
    assert (await client.delete(f"/api/v1/chat/conversations/{created['id']}", headers=stranger)).status_code == 404
    deleted = await client.delete(f"/api/v1/chat/conversations/{created['id']}", headers=owner)
    assert deleted.json() == {"detail": "Conversation deleted"}
    assert (await client.get(f"/api/v1/chat/conversations/{created['id']}", headers=owner)).status_code == 404
