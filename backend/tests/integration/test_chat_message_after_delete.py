"""A chat message written after its conversation was deleted leaves nothing behind."""

import pytest

from app.repositories.chat import ChatRepository


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_message_for_a_deleted_conversation_is_discarded(db):
    repo = ChatRepository(db)
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    await repo.delete_conversation(conv["_id"], user_id="user-1")

    assert await repo.add_message(conv["_id"], role="assistant", content="late answer") is None
    assert await db["chat_messages"].count_documents({}) == 0
