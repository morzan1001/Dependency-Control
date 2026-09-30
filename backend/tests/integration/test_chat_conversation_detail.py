"""GET /chat/conversations/{id} serves stored messages, including ones written by older releases."""

from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.core.permissions import Permissions
from tests.helpers.auth import bearer_headers

_USER = "chat-user"
_CONVERSATION = "conv-legacy"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_message_stored_with_images_is_served_without_them(client, db, monkeypatch):
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
