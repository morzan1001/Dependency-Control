"""Unit tests for ChatRepository using the FakeDb fixture from conftest.py."""

import asyncio

import pytest
import pytest_asyncio

from app.repositories.chat import ChatRepository


@pytest_asyncio.fixture
async def repo(db):
    return ChatRepository(db)


@pytest.mark.asyncio
async def test_create_conversation(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    assert conv["user_id"] == "user-1"
    assert conv["title"] == "My Chat"
    assert conv["message_count"] == 0


@pytest.mark.asyncio
async def test_list_conversations(repo):
    await repo.create_conversation(user_id="user-1", title="Chat A")
    await repo.create_conversation(user_id="user-1", title="Chat B")
    await repo.create_conversation(user_id="user-2", title="Other User")

    result = await repo.list_conversations(user_id="user-1")
    assert len(result) == 2
    titles = {c["title"] for c in result}
    assert titles == {"Chat A", "Chat B"}


@pytest.mark.asyncio
async def test_get_conversation(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    found = await repo.get_conversation(conv["_id"], user_id="user-1")
    assert found is not None
    assert found["title"] == "My Chat"


@pytest.mark.asyncio
async def test_get_conversation_wrong_user(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    found = await repo.get_conversation(conv["_id"], user_id="user-2")
    assert found is None


@pytest.mark.asyncio
async def test_add_message_returns_the_conversations_new_message_count(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    assert await repo.add_message(conv["_id"], role="user", content="Hello") == 1
    assert await repo.add_message(conv["_id"], role="assistant", content="Hi") == 2


@pytest.mark.asyncio
async def test_delete_conversation(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    await repo.add_message(conv["_id"], role="user", content="Hello")

    deleted = await repo.delete_conversation(conv["_id"], user_id="user-1")
    assert deleted is True

    found = await repo.get_conversation(conv["_id"], user_id="user-1")
    assert found is None

    messages = await repo.get_recent_messages(conv["_id"])
    assert len(messages) == 0


@pytest.mark.asyncio
async def test_delete_conversation_wrong_user(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    await repo.add_message(conv["_id"], role="user", content="Hello")

    deleted = await repo.delete_conversation(conv["_id"], user_id="user-2")

    assert deleted is False
    assert await repo.get_conversation(conv["_id"], user_id="user-1") is not None
    assert len(await repo.get_recent_messages(conv["_id"])) == 1


@pytest.mark.asyncio
async def test_add_and_get_messages(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")

    await repo.add_message(conv["_id"], role="user", content="Hello")
    await asyncio.sleep(0.01)  # a later millisecond, so the order does not rest on a created_at tie
    await repo.add_message(conv["_id"], role="assistant", content="Hi there!")

    messages = await repo.get_recent_messages(conv["_id"])
    assert len(messages) == 2
    assert messages[0]["role"] == "user"
    assert messages[1]["role"] == "assistant"

    updated = await repo.get_conversation(conv["_id"], user_id="user-1")
    assert updated["message_count"] == 2


@pytest.mark.asyncio
async def test_a_stored_message_has_no_images_field(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")
    await repo.add_message(conv["_id"], role="user", content="Hello")

    (message,) = await repo.get_recent_messages(conv["_id"])
    assert "images" not in message


@pytest.mark.asyncio
async def test_add_message_with_tool_calls(repo):
    conv = await repo.create_conversation(user_id="user-1", title="My Chat")

    await repo.add_message(
        conv["_id"],
        role="assistant",
        content="Found your projects",
        tool_calls=[
            {
                "tool_name": "list_projects",
                "arguments": {},
                "result": {"projects": []},
                "duration_ms": 50,
            }
        ],
    )

    messages = await repo.get_recent_messages(conv["_id"])
    assert len(messages) == 1
    assert messages[0]["tool_calls"][0]["tool_name"] == "list_projects"
    assert "token_count" not in messages[0]
