"""Tests for ChatService orchestration (mocks Ollama + DB)."""

import asyncio
from typing import Any, AsyncIterator, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.services.chat.service as service_mod
from app.models.user import User
from app.services.chat.service import ChatService


def _make_user(user_id: str = "user-1", permissions: list[str] | None = None) -> User:
    """Build a minimal User object for tests."""
    return User.model_validate(
        {
            "_id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "hashed_password": None,
            "is_active": True,
            "is_verified": True,
            "auth_provider": "local",
            "permissions": permissions or ["chat:access"],
        }
    )


async def _async_gen(chunks: List[Dict[str, Any]]) -> AsyncIterator[Dict[str, Any]]:
    for c in chunks:
        yield c


def _make_service() -> ChatService:
    """Build a ChatService with all collaborators replaced by mocks."""
    db = MagicMock()
    # send_message reads chat_max_tool_rounds from system_settings at runtime;
    # stub it to return an empty doc so the config.py default applies.
    db["system_settings"].find_one = AsyncMock(return_value=None)
    service = ChatService(db)

    # Replace repo methods
    service.repo = MagicMock()
    service.repo.add_message = AsyncMock(return_value={"_id": "msg-1"})
    service.repo.get_conversation = AsyncMock(
        return_value={
            "_id": "conv-1",
            "user_id": "user-1",
            "title": "Test",
            "message_count": 1,
        }
    )
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
    service.ollama.chat_stream = MagicMock(
        return_value=_async_gen(
            [
                {"type": "token", "content": "Hello"},
                {"type": "token", "content": " world"},
                {"type": "done", "total_tokens": 2, "eval_rate": 100.0},
            ]
        )
    )

    events = []
    async for chunk in service.send_message("conv-1", user, "hi"):
        events.append(chunk)

    # Token events + done
    types = [c.split('"type":')[1].split(",")[0].split('"')[1] if '"type":' in c else "" for c in events]
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

    service.ollama.chat_stream = MagicMock(
        return_value=_async_gen(
            [
                {"type": "token", "content": "ok"},
                {"type": "done", "total_tokens": 1, "eval_rate": 50.0},
            ]
        )
    )

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
    service.ollama.chat_stream = MagicMock(
        side_effect=[
            _async_gen(
                [
                    {"type": "tool_call", "function": {"name": "list_projects", "arguments": {}}},
                    {"type": "done", "total_tokens": 10, "eval_rate": 50.0},
                ]
            ),
            _async_gen(
                [
                    {"type": "token", "content": "Projects listed"},
                    {"type": "done", "total_tokens": 5, "eval_rate": 50.0},
                ]
            ),
        ]
    )

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

    service.ollama.chat_stream = MagicMock(
        return_value=_async_gen(
            [
                {"type": "error", "message": "Ollama unavailable"},
            ]
        )
    )

    events = [c async for c in service.send_message("conv-1", user, "hi")]

    combined = "".join(events)
    assert "error" in combined
    assert "Ollama unavailable" in combined
    # Ollama returned an error immediately — no tokens were streamed.
    # client_notified_of_error=True and full_response="" so the finally block
    # must NOT save a spurious assistant message.
    # Expected: exactly 1 call (user message only).
    assert service.repo.add_message.call_count == 1


@pytest.mark.asyncio
async def test_current_user_message_not_duplicated_in_prompt():
    """Regression: the just-saved user turn must appear exactly once in the
    Ollama prompt. Previously history was loaded AFTER add_message, so
    get_recent_messages returned the new message and build_messages appended
    it again -> the turn (and its images) showed up twice."""
    service = _make_service()
    user = _make_user()

    # In-memory store so get_recent_messages reflects what add_message persisted
    # (mirrors the real repo: sorted by created_at ascending).
    stored: List[Dict[str, Any]] = []

    async def fake_add(conversation_id, role, content="", images=None, **kwargs):
        stored.append(
            {
                "role": role,
                "content": content,
                "images": images or [],
                "tool_calls": kwargs.get("tool_calls") or [],
            }
        )
        return {"_id": f"msg-{len(stored)}"}

    async def fake_recent(conversation_id, limit=20):
        return list(stored)

    service.repo.add_message = AsyncMock(side_effect=fake_add)
    service.repo.get_recent_messages = AsyncMock(side_effect=fake_recent)

    captured: Dict[str, Any] = {}

    def capture_chat_stream(messages, tools=None):
        captured["messages"] = [dict(m) for m in messages]
        return _async_gen(
            [
                {"type": "token", "content": "ok"},
                {"type": "done", "total_tokens": 1, "eval_rate": 1.0},
            ]
        )

    service.ollama.chat_stream = MagicMock(side_effect=capture_chat_stream)

    async for _ in service.send_message("conv-1", user, "which project is worst?"):
        pass

    user_turns = [
        m for m in captured["messages"] if m.get("role") == "user" and m.get("content") == "which project is worst?"
    ]
    assert len(user_turns) == 1, f"user message should appear once, got {len(user_turns)}"


@pytest.mark.asyncio
async def test_warmup_task_cancelled_on_client_disconnect(monkeypatch):
    """Regression: if the SSE client disconnects during cold-start warm-up, the
    shielded first-chunk task must be cancelled instead of leaking and keeping
    Ollama/GPU busy in the background."""
    # Shorten the keepalive slice so the warm-up loop emits an info event fast.
    monkeypatch.setattr(service_mod, "_WARMUP_SLICE_SECONDS", 0.02)

    service = _make_service()
    user = _make_user()

    started = asyncio.Event()
    cancelled = {"value": False}

    class HangingStream:
        def __aiter__(self):
            return self

        async def __anext__(self):
            started.set()
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                cancelled["value"] = True
                raise
            return {"type": "token", "content": "x"}

    service.ollama.chat_stream = MagicMock(return_value=HangingStream())

    agen = service.send_message("conv-1", user, "hi")
    # Pull the first warm-up keepalive info event (proves we're mid warm-up).
    first = await agen.__anext__()
    assert '"type": "info"' in first

    # Client disconnects -> Starlette closes the async generator.
    await agen.aclose()
    # Give the loop a tick for cancellation to propagate into the task.
    await asyncio.sleep(0.05)

    assert cancelled["value"] is True, "warm-up task must be cancelled on disconnect"


@pytest.mark.asyncio
async def test_create_conversation_uses_repo():
    service = _make_service()
    user = _make_user()

    conv = await service.create_conversation(user, title="Hello")
    assert conv["_id"] == "conv-new"
    service.repo.create_conversation.assert_awaited_once_with(
        user_id="user-1",
        title="Hello",
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
