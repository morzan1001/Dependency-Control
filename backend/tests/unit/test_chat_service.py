"""Tests for ChatService orchestration (mocks Ollama + DB)."""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import anyio
import pytest
from prometheus_client import REGISTRY

import app.services.chat.service as service_mod
from app.core.config import settings
from app.models.user import User
from app.services.chat.service import ChatService
from app.services.chat.tools import ChatToolRegistry


def _make_user(user_id: str = "user-1", permissions: list[str] | None = None) -> User:
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


async def _async_gen(chunks: list[dict[str, Any]]) -> AsyncIterator[dict[str, Any]]:
    for c in chunks:
        yield c


async def _dying_gen(chunks: list[dict[str, Any]], error: Exception) -> AsyncIterator[dict[str, Any]]:
    for c in chunks:
        yield c
    raise error


def _turns(status: str) -> float:
    return REGISTRY.get_sample_value("dc_chat_messages_total", {"status": status}) or 0.0


def _tokens(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str).encode()) // 4


def _in_memory_store(service: ChatService) -> list[dict[str, Any]]:
    stored: list[dict[str, Any]] = []

    async def fake_add(conversation_id, role, content="", **kwargs):
        stored.append({"role": role, "content": content, "tool_calls": kwargs.get("tool_calls") or []})
        return len(stored)

    async def fake_recent(conversation_id, limit=20):
        return list(stored)

    service.repo.add_message = AsyncMock(side_effect=fake_add)
    service.repo.get_recent_messages = AsyncMock(side_effect=fake_recent)
    return stored


_LIST_PROJECTS = {"type": "tool_call", "function": {"name": "list_projects", "arguments": {}}}
_DONE = {"type": "done", "total_tokens": 3, "eval_rate": 10.0}


def _make_service() -> ChatService:
    db = MagicMock()
    service = ChatService(db)

    service.repo = MagicMock()
    service.repo.add_message = AsyncMock(return_value=1)
    service.repo.get_conversation = AsyncMock(
        side_effect=AssertionError("the title must follow the write, not a read-back")
    )
    service.repo.update_conversation_title = AsyncMock()
    service.repo.get_recent_messages = AsyncMock(return_value=[])
    service.repo.create_conversation = AsyncMock(
        return_value={"_id": "conv-new", "user_id": "user-1", "title": "New", "message_count": 0}
    )

    service.tools = MagicMock()
    service.tools.get_available_tool_definitions = MagicMock(return_value=[])
    service.tools.execute_tool = AsyncMock(return_value={"ok": True})

    service.ollama = MagicMock()
    return service


@pytest.mark.asyncio
async def test_send_message_streams_tokens_and_persists():
    service = _make_service()
    user = _make_user()

    service.ollama.chat_stream = MagicMock(
        return_value=_async_gen(
            [
                {"type": "token", "content": "Hello"},
                {"type": "token", "content": " world"},
                {"type": "done", "total_tokens": 2, "eval_rate": 100.0},
            ]
        )
    )

    events = [chunk async for chunk in service.send_message("conv-1", user, "hi", max_tool_rounds=20)]

    types = [c.split('"type":')[1].split(",")[0].split('"')[1] if '"type":' in c else "" for c in events]
    assert "token" in types
    assert "done" in types

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

    async for _ in service.send_message("conv-1", user, "my very first question", max_tool_rounds=20):
        pass

    service.repo.update_conversation_title.assert_awaited_once()
    args = service.repo.update_conversation_title.await_args
    assert args.args[0] == "conv-1"
    assert args.args[1] == "user-1"
    assert "first question" in args.args[2]


@pytest.mark.asyncio
async def test_a_later_message_does_not_retitle_the_conversation():
    service = _make_service()
    user = _make_user()
    service.repo.add_message = AsyncMock(return_value=7)

    service.ollama.chat_stream = MagicMock(
        return_value=_async_gen(
            [
                {"type": "token", "content": "ok"},
                {"type": "done", "total_tokens": 1, "eval_rate": 50.0},
            ]
        )
    )

    async for _ in service.send_message("conv-1", user, "a follow-up question", max_tool_rounds=20):
        pass

    service.repo.update_conversation_title.assert_not_awaited()


@pytest.mark.asyncio
async def test_tool_rounds_exhausted_without_text_still_answers_the_user():
    service = _make_service()
    user = _make_user()

    def tool_only_round(messages, tools=None):
        return _async_gen(
            [
                {"type": "tool_call", "function": {"name": "list_projects", "arguments": {}}},
                {"type": "done", "total_tokens": 3, "eval_rate": 10.0},
            ]
        )

    service.ollama.chat_stream = MagicMock(side_effect=tool_only_round)

    events = [c async for c in service.send_message("conv-1", user, "why is it slow?", max_tool_rounds=2)]

    assert "reasoning budget" in "".join(events)
    assistant_call = service.repo.add_message.call_args_list[-1]
    assert assistant_call.kwargs["role"] == "assistant"
    assert "reasoning budget" in assistant_call.kwargs["content"]
    assert len(assistant_call.kwargs["tool_calls"]) == 2


@pytest.mark.asyncio
async def test_a_stream_dying_after_some_text_persists_the_partial_answer():
    service = _make_service()
    user = _make_user()
    service.ollama.chat_stream = MagicMock(
        return_value=_dying_gen(
            [{"type": "token", "content": "Half an answer"}],
            RuntimeError("connection reset by peer"),
        )
    )

    with pytest.raises(RuntimeError):
        async for _ in service.send_message("conv-1", user, "hi", max_tool_rounds=20):
            pass

    assistant_call = service.repo.add_message.call_args_list[-1]
    assert assistant_call.kwargs["role"] == "assistant"
    assert assistant_call.kwargs["content"].startswith("Half an answer")
    assert "_[stream interrupted]_" in assistant_call.kwargs["content"]


@pytest.mark.asyncio
async def test_a_stream_dying_after_a_tool_call_keeps_the_tool_result():
    service = _make_service()
    user = _make_user()
    service.ollama.chat_stream = MagicMock(
        return_value=_dying_gen(
            [{"type": "tool_call", "function": {"name": "list_projects", "arguments": {}}}],
            RuntimeError("connection reset by peer"),
        )
    )

    with pytest.raises(RuntimeError):
        async for _ in service.send_message("conv-1", user, "list projects", max_tool_rounds=20):
            pass

    assistant_call = service.repo.add_message.call_args_list[-1]
    assert assistant_call.kwargs["role"] == "assistant"
    assert [c["tool_name"] for c in assistant_call.kwargs["tool_calls"]] == ["list_projects"]
    assert assistant_call.kwargs["content"] == "_[stream interrupted]_"


@pytest.mark.asyncio
async def test_send_message_executes_tool_call():
    service = _make_service()
    user = _make_user()

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

    events = [c async for c in service.send_message("conv-1", user, "list projects", max_tool_rounds=20)]

    combined = "".join(events)
    assert "tool_call_start" in combined
    assert "tool_call_end" in combined
    assert "list_projects" in combined

    service.tools.execute_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_message_error_stops_stream():
    service = _make_service()
    user = _make_user()
    errors, interrupted = _turns("error"), _turns("interrupted")

    service.ollama.chat_stream = MagicMock(
        return_value=_async_gen(
            [
                {"type": "error", "message": "Ollama unavailable"},
            ]
        )
    )

    events = [c async for c in service.send_message("conv-1", user, "hi", max_tool_rounds=20)]

    combined = "".join(events)
    assert "error" in combined
    assert "Ollama unavailable" in combined
    assert service.repo.add_message.call_count == 2
    assistant_call = service.repo.add_message.call_args_list[-1]
    assert assistant_call.kwargs["role"] == "assistant"
    assert assistant_call.kwargs["content"] == "_[stream interrupted]_"
    assert (_turns("error"), _turns("interrupted")) == (errors + 1, interrupted)


@pytest.mark.asyncio
async def test_a_turn_for_a_deleted_conversation_ends_before_the_model_runs():
    service = _make_service()
    service.repo.add_message = AsyncMock(return_value=None)
    service.ollama.chat_stream = MagicMock(side_effect=AssertionError("the model must not run"))

    events = [c async for c in service.send_message("conv-gone", _make_user(), "hi", max_tool_rounds=20)]

    assert events == ['data: {"type": "error", "message": "Conversation not found"}\n\n']
    assert service.repo.add_message.await_count == 1
    service.repo.update_conversation_title.assert_not_awaited()


@pytest.mark.asyncio
async def test_current_user_message_not_duplicated_in_prompt():
    """The just-saved user turn must appear exactly once in the Ollama prompt."""
    service = _make_service()
    user = _make_user()

    _in_memory_store(service)

    captured: dict[str, Any] = {}

    def capture_chat_stream(messages, tools=None):
        captured["messages"] = [dict(m) for m in messages]
        return _async_gen(
            [
                {"type": "token", "content": "ok"},
                {"type": "done", "total_tokens": 1, "eval_rate": 1.0},
            ]
        )

    service.ollama.chat_stream = MagicMock(side_effect=capture_chat_stream)

    async for _ in service.send_message("conv-1", user, "which project is worst?", max_tool_rounds=20):
        pass

    user_turns = [
        m for m in captured["messages"] if m.get("role") == "user" and m.get("content") == "which project is worst?"
    ]
    assert len(user_turns) == 1, f"user message should appear once, got {len(user_turns)}"


@pytest.mark.asyncio
async def test_warmup_task_cancelled_on_client_disconnect(monkeypatch):
    """A client disconnect during warm-up must cancel the shielded first-chunk task."""
    # Shorten the keepalive slice so the warm-up loop emits a heartbeat fast.
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

    agen = service.send_message("conv-1", user, "hi", max_tool_rounds=20)
    # First heartbeat comment proves we are mid warm-up.
    first = await agen.__anext__()
    assert first.startswith(": keepalive")

    # aclose simulates the client disconnecting.
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
async def test_a_follow_up_replays_the_tool_turn_exactly_as_it_happened_live():
    service = _make_service()
    _in_memory_store(service)
    sent: list[list[dict[str, Any]]] = []
    rounds = iter(
        [
            [_LIST_PROJECTS, _DONE],
            [{"type": "token", "content": "Two projects."}, _DONE],
            [{"type": "token", "content": "ok"}, _DONE],
        ]
    )

    def record(messages, tools=None):
        sent.append([dict(m) for m in messages])
        return _async_gen(next(rounds))

    service.ollama.chat_stream = MagicMock(side_effect=record)

    async for _ in service.send_message("conv-1", _make_user(), "list projects", max_tool_rounds=20):
        pass
    async for _ in service.send_message("conv-1", _make_user(), "and the worst?", max_tool_rounds=20):
        pass

    live_second_round, replay = sent[1], sent[2]
    assert replay[:-1] == [*live_second_round, {"role": "assistant", "content": "Two projects."}]


@pytest.mark.asyncio
async def test_text_from_a_tool_calling_round_is_not_the_answer():
    service = _make_service()
    service.ollama.chat_stream = MagicMock(
        side_effect=[
            _async_gen([{"type": "token", "content": "Let me check. "}, _LIST_PROJECTS, _DONE]),
            _async_gen([{"type": "token", "content": "Two projects."}, _DONE]),
        ]
    )

    async for _ in service.send_message("conv-1", _make_user(), "list projects", max_tool_rounds=20):
        pass

    assert service.repo.add_message.call_args_list[-1].kwargs["content"] == "Two projects."


@pytest.mark.asyncio
async def test_rounds_exhausted_after_a_preface_each_round_still_answers_with_the_fallback():
    service = _make_service()
    service.ollama.chat_stream = MagicMock(
        side_effect=lambda messages, tools=None: _async_gen(
            [{"type": "token", "content": "Let me check. "}, _LIST_PROJECTS, _DONE]
        )
    )
    exhausted, successes = _turns("max_rounds_exhausted"), _turns("success")

    events = [c async for c in service.send_message("conv-1", _make_user(), "why?", max_tool_rounds=2)]

    stored = service.repo.add_message.call_args_list[-1].kwargs["content"]
    assert "reasoning budget" in stored
    assert "Let me check" not in stored
    assert "reasoning budget" in "".join(events)
    assert (_turns("max_rounds_exhausted"), _turns("success")) == (exhausted + 1, successes)


@pytest.mark.asyncio
async def test_an_empty_completion_is_answered_with_a_fallback_not_saved_as_success():
    service = _make_service()
    service.ollama.chat_stream = MagicMock(return_value=_async_gen([_DONE]))
    empty, successes = _turns("empty_response"), _turns("success")

    events = [c async for c in service.send_message("conv-1", _make_user(), "hi", max_tool_rounds=20)]

    stored = service.repo.add_message.call_args_list[-1].kwargs["content"]
    assert "empty response" in stored
    assert stored in "".join(events).replace("\\n", "\n")
    assert (_turns("empty_response"), _turns("success")) == (empty + 1, successes)


@pytest.mark.asyncio
async def test_a_client_disconnect_still_saves_the_interrupted_turn():
    service = _make_service()
    saved: list[tuple[str, str]] = []

    async def insert_after_io(conversation_id, role, content="", **kwargs):
        await asyncio.sleep(0.01)
        saved.append((role, content))
        return len(saved)

    service.repo.add_message = AsyncMock(side_effect=insert_after_io)

    async def answer_then_hang():
        yield {"type": "token", "content": "partial answer"}
        await asyncio.sleep(3600)

    service.ollama.chat_stream = MagicMock(return_value=answer_then_hang())
    interrupted = _turns("interrupted")

    # Starlette cancels the response's task group when the client goes away.
    with anyio.CancelScope() as request_scope:
        async for event in service.send_message("conv-1", _make_user(), "hi", max_tool_rounds=20):
            if "partial answer" in event:
                request_scope.cancel()

    assert saved == [("user", "hi"), ("assistant", "partial answer\n\n_[stream interrupted]_")]
    assert _turns("interrupted") == interrupted + 1


@pytest.mark.asyncio
async def test_a_tool_call_records_how_long_the_tool_itself_took():
    service = _make_service()

    async def slow_model_then_tool_call():
        await asyncio.sleep(0.3)
        yield _LIST_PROJECTS
        yield _DONE

    service.ollama.chat_stream = MagicMock(
        side_effect=[slow_model_then_tool_call(), _async_gen([{"type": "token", "content": "ok"}, _DONE])]
    )

    async for _ in service.send_message("conv-1", _make_user(), "list projects", max_tool_rounds=20):
        pass

    (call,) = service.repo.add_message.call_args_list[-1].kwargs["tool_calls"]
    assert call["duration_ms"] < 100


@pytest.mark.asyncio
async def test_every_prompt_sent_to_ollama_leaves_room_for_the_reply():
    service = _make_service()
    service.repo.get_recent_messages = AsyncMock(
        return_value=[{"role": ("user", "assistant")[i % 2], "content": "history " * 750} for i in range(15)]
    )
    service.tools.get_available_tool_definitions = ChatToolRegistry().get_available_tool_definitions
    service.tools.execute_tool = AsyncMock(return_value={"rows": ["x" * 90] * 80})
    prompt_sizes: list[int] = []

    def record(messages, tools=None):
        prompt_sizes.append(sum(_tokens(m) for m in messages) + _tokens(tools))
        if len(prompt_sizes) < 4:
            return _async_gen([_LIST_PROJECTS, _DONE])
        return _async_gen([{"type": "token", "content": "ok"}, _DONE])

    service.ollama.chat_stream = MagicMock(side_effect=record)

    async for _ in service.send_message("conv-1", _make_user(), "summarise", max_tool_rounds=20):
        pass

    assert len(prompt_sizes) == 4
    assert max(prompt_sizes) <= settings.OLLAMA_NUM_CTX - 2048
