"""Tests for ChatService orchestration (mocks Ollama + DB)."""

from typing import Any, AsyncIterator, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.user import User
from app.services.chat.service import ChatService


def _make_user(user_id: str = "user-1", permissions: list[str] | None = None) -> User:
    """Build a minimal User object for tests."""
    return User.model_validate({
        "_id": user_id,
        "username": "testuser",
        "email": "test@example.com",
        "hashed_password": None,
        "is_active": True,
        "is_verified": True,
        "auth_provider": "local",
        "permissions": permissions or ["chat:access"],
    })


async def _async_gen(chunks: List[Dict[str, Any]]) -> AsyncIterator[Dict[str, Any]]:
    for c in chunks:
        yield c


def _make_service() -> ChatService:
    """Build a ChatService with all collaborators replaced by mocks."""
    db = MagicMock()
    service = ChatService(db)

    # Replace repo methods
    service.repo = MagicMock()
    service.repo.add_message = AsyncMock(return_value={"_id": "msg-1"})
    service.repo.get_conversation = AsyncMock(return_value={
        "_id": "conv-1", "user_id": "user-1", "title": "Test", "message_count": 1,
    })
    service.repo.update_conversation_title = AsyncMock()
    service.repo.get_recent_messages = AsyncMock(return_value=[])
    service.repo.list_conversations = AsyncMock(return_value=[])
    service.repo.create_conversation = AsyncMock(
        return_value={"_id": "conv-new", "user_id": "user-1", "title": "New", "message_count": 0}
    )
    service.repo.delete_conversation = AsyncMock(return_value=True)
    service.repo.get_messages = AsyncMock(return_value=[])

    # Replace tools registry
    service.tools = MagicMock()
    service.tools.get_available_tool_definitions = MagicMock(return_value=[])
    service.tools.execute_tool = AsyncMock(return_value={"ok": True})

    # Ollama stubbed per-test
    service.ollama = MagicMock()
    return service


@pytest.mark.asyncio
async def test_send_message_streams_tokens_and_persists():
    service = _make_service()
    user = _make_user()

    # Ollama yields two tokens then done (no tool calls)
    service.ollama.chat_stream = MagicMock(return_value=_async_gen([
        {"type": "token", "content": "Hello"},
        {"type": "token", "content": " world"},
        {"type": "done", "total_tokens": 2, "eval_rate": 100.0},
    ]))

    events = []
    async for chunk in service.send_message("conv-1", user, "hi"):
        events.append(chunk)

    # Token events + done
    types = [c.split('"type":')[1].split(',')[0].split('"')[1] if '"type":' in c else '' for c in events]
    assert "token" in types
    assert "done" in types

    # User message + assistant message persisted
    assert service.repo.add_message.call_count == 2
    assistant_call = service.repo.add_message.call_args_list[-1]
    assert assistant_call.kwargs["role"] == "assistant"
    assert assistant_call.kwargs["content"] == "Hello world"


@pytest.mark.asyncio
async def test_send_message_auto_titles_first_message():
    service = _make_service()
    user = _make_user()

    service.ollama.chat_stream = MagicMock(return_value=_async_gen([
        {"type": "token", "content": "ok"},
        {"type": "done", "total_tokens": 1, "eval_rate": 50.0},
    ]))

    async for _ in service.send_message("conv-1", user, "my very first question"):
        pass

    # message_count == 1 in mocked conv, so title update runs
    service.repo.update_conversation_title.assert_awaited_once()
    args = service.repo.update_conversation_title.await_args
    # positional args: conv_id, user_id, title
    assert args.args[0] == "conv-1"
    assert args.args[1] == "user-1"
    assert "first question" in args.args[2]


@pytest.mark.asyncio
async def test_send_message_executes_tool_call():
    service = _make_service()
    user = _make_user()

    # Ollama first yields a tool call, then done. In the second round: done again.
    service.ollama.chat_stream = MagicMock(side_effect=[
        _async_gen([
            {"type": "tool_call", "function": {"name": "list_projects", "arguments": {}}},
            {"type": "done", "total_tokens": 10, "eval_rate": 50.0},
        ]),
        _async_gen([
            {"type": "token", "content": "Projects listed"},
            {"type": "done", "total_tokens": 5, "eval_rate": 50.0},
        ]),
    ])

    events = [c async for c in service.send_message("conv-1", user, "list projects")]

    # Expect tool_call_start + tool_call_end events present
    combined = "".join(events)
    assert "tool_call_start" in combined
    assert "tool_call_end" in combined
    assert "list_projects" in combined

    # Tool was executed exactly once
    service.tools.execute_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_message_error_stops_stream():
    service = _make_service()
    user = _make_user()

    service.ollama.chat_stream = MagicMock(return_value=_async_gen([
        {"type": "error", "message": "Ollama unavailable"},
    ]))

    events = [c async for c in service.send_message("conv-1", user, "hi")]

    combined = "".join(events)
    assert "error" in combined
    assert "Ollama unavailable" in combined
    # On error the finally block persists an interrupted-marker so the user
    # doesn't see a dangling user turn on reload.
    # Expected: 1 call for the user message + 1 call for the interrupted marker.
    assert service.repo.add_message.call_count == 2
    # Verify the interrupted marker was saved as the assistant role
    last_call_kwargs = service.repo.add_message.call_args_list[-1]
    assert last_call_kwargs.kwargs.get("role") == "assistant" or last_call_kwargs.args[1] == "assistant"


@pytest.mark.asyncio
async def test_create_conversation_uses_repo():
    service = _make_service()
    user = _make_user()

    conv = await service.create_conversation(user, title="Hello")
    assert conv["_id"] == "conv-new"
    service.repo.create_conversation.assert_awaited_once_with(
        user_id="user-1", title="Hello",
    )


@pytest.mark.asyncio
async def test_delete_conversation_scoped_to_user():
    service = _make_service()
    user = _make_user()

    result = await service.delete_conversation("conv-1", user)
    assert result is True
    service.repo.delete_conversation.assert_awaited_once_with("conv-1", user_id="user-1")


@pytest.mark.asyncio
async def test_get_messages_returns_empty_when_conversation_missing():
    service = _make_service()
    service.repo.get_conversation = AsyncMock(return_value=None)
    user = _make_user()

    msgs = await service.get_messages("conv-missing", user)
    assert msgs == []
    service.repo.get_messages.assert_not_called()
