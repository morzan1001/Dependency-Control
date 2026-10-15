import asyncio
import json
import time
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import aclosing
from dataclasses import dataclass, field
from typing import Any

import anyio
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.metrics import (
    chat_conversations_created_total,
    chat_first_token_seconds,
    chat_messages_total,
    chat_ollama_tokens_generated_total,
    chat_ollama_tokens_per_second,
    chat_response_duration_seconds,
    chat_tool_calls_per_message,
)
from app.models.user import User
from app.repositories.chat import ChatRepository
from app.services.chat.context import (
    build_messages,
    message_token_budget,
    tool_exchange_messages,
    trim_to_token_budget,
)
from app.services.chat.ollama_client import OllamaClient
from app.services.chat.tools import ChatToolRegistry

_WARMUP_SLICE_SECONDS = 10.0

_KEEPALIVE = {"type": "keepalive"}
_INTERRUPTED = "_[stream interrupted]_"
_EMPTY_ANSWER = "_The model returned an empty response. Please try again or rephrase the question._"
_ROUNDS_EXHAUSTED = (
    "_I gathered data from {calls} tool call(s) but couldn't put together a "
    "final answer within my reasoning budget. The tool results "
    "above contain the raw data — please ask a more specific "
    "follow-up question and I'll try again._"
)


def _sse(event: str, **data: Any) -> str:
    return f"data: {json.dumps({'type': event, **data}, default=str)}\n\n"


async def _chunks(stream: AsyncIterator[dict[str, Any]], *, warming: bool) -> AsyncGenerator[dict[str, Any], None]:
    if warming:
        # A cold load (60-90s) outlasts proxy idle timeouts; asyncio.wait, unlike wait_for, spares the fetch on timeout.
        first = asyncio.ensure_future(anext(stream, None))
        try:
            while not (await asyncio.wait({first}, timeout=_WARMUP_SLICE_SECONDS))[0]:
                yield _KEEPALIVE
        finally:
            # A client leaving mid-wait must cancel the fetch, else it keeps pinning Ollama/GPU.
            if not first.done():
                first.cancel()
                await asyncio.gather(first, return_exceptions=True)
        if (chunk := first.result()) is None:
            return
        yield chunk
    async for chunk in stream:
        yield chunk


@dataclass
class _Turn:
    messages: list[dict[str, Any]]
    budget: int
    started: float
    answer: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    round_tool_calls: int = 0
    first_token: bool = False
    failed: bool = False

    def settle(self) -> tuple[str, str | None]:
        if self.round_tool_calls:
            status, self.answer = "max_rounds_exhausted", _ROUNDS_EXHAUSTED.format(calls=len(self.tool_calls))
        elif not self.answer.strip():
            status, self.answer = "empty_response", _EMPTY_ANSWER
        else:
            return "success", None
        return status, f"\n\n{self.answer}" if self.first_token else self.answer

    def interrupt(self) -> str:
        self.answer = f"{self.answer}\n\n{_INTERRUPTED}" if self.answer else _INTERRUPTED
        return "error" if self.failed else "interrupted"


class ChatService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.repo = ChatRepository(db)
        self.ollama = OllamaClient()
        self.tools = ChatToolRegistry()

    async def create_conversation(self, user: User, title: str | None = None) -> dict[str, Any]:
        chat_conversations_created_total.inc()
        return await self.repo.create_conversation(
            user_id=str(user.id),
            title=title or "New Conversation",
        )

    async def send_message(
        self,
        conversation_id: str,
        user: User,
        content: str,
        *,
        max_tool_rounds: int,
    ) -> AsyncIterator[str]:
        started = time.time()
        # Load history before persisting the new message so the current turn isn't replayed twice.
        history = await self.repo.get_recent_messages(conversation_id, limit=settings.CHAT_MAX_HISTORY_MESSAGES)

        message_count = await self.repo.add_message(conversation_id, role="user", content=content)
        if message_count is None:
            yield _sse("error", message="Conversation not found")
            return
        if message_count == 1:
            title = content[:80] + ("..." if len(content) > 80 else "")
            await self.repo.update_conversation_title(conversation_id, str(user.id), title)

        tools = self.tools.get_available_tool_definitions(user.permissions)
        budget = message_token_budget(tools)
        turn = _Turn(build_messages(history, content, budget), budget, started)
        saved = False
        try:
            for _ in range(max_tool_rounds):
                async with aclosing(self._model_round(turn, tools, user)) as events:
                    async for event in events:
                        yield event
                if turn.failed:
                    return
                if not turn.round_tool_calls:
                    break

            status, fallback = turn.settle()
            if fallback:
                yield _sse("token", content=fallback)
            await self._persist_assistant(conversation_id, turn, status)
            saved = True
            chat_response_duration_seconds.observe(time.time() - started)
            chat_tool_calls_per_message.observe(len(turn.tool_calls))
            yield _sse("done")
        finally:
            if not saved:
                # A client disconnect cancels the response's scope; the save must still land.
                with anyio.CancelScope(shield=True):
                    await self._persist_assistant(conversation_id, turn, turn.interrupt())

    async def _model_round(self, turn: _Turn, tools: list[dict[str, Any]], user: User) -> AsyncGenerator[str, None]:
        # Only the last round's text answers the question; earlier rounds only led up to tool calls.
        turn.answer, turn.round_tool_calls = "", 0
        stream = self.ollama.chat_stream(turn.messages, tools=tools)
        # Only the turn's first round can meet a cold model.
        async with aclosing(_chunks(stream, warming=not turn.tool_calls)) as chunks:
            async for chunk in chunks:
                kind = chunk["type"]
                if kind == "keepalive":
                    yield ": keepalive\n\n"
                elif kind == "token":
                    if not turn.first_token:
                        chat_first_token_seconds.observe(time.time() - turn.started)
                        turn.first_token = True
                    turn.answer += chunk["content"]
                    yield _sse("token", content=chunk["content"])
                elif kind == "tool_call":
                    function = chunk["function"]
                    name, arguments = function.get("name", "unknown"), function.get("arguments", {})
                    yield _sse("tool_call_start", tool_name=name)
                    result = await self._call_tool(turn, name, arguments, user)
                    yield _sse("tool_call_end", tool_name=name, arguments=arguments, result=result)
                elif kind == "done":
                    chat_ollama_tokens_generated_total.inc(chunk.get("total_tokens", 0))
                    chat_ollama_tokens_per_second.set(chunk.get("eval_rate", 0))
                    return
                elif kind == "error":
                    yield _sse("error", message=chunk["message"])
                    turn.failed = True
                    return

    async def _call_tool(self, turn: _Turn, name: str, arguments: Any, user: User) -> dict[str, Any]:
        turn.round_tool_calls += 1
        tool_start = time.monotonic()
        result = await self.tools.execute_tool(name, arguments, user, self.db)
        call = {
            "tool_name": name,
            "arguments": arguments,
            "result": result,
            "duration_ms": int((time.monotonic() - tool_start) * 1000),
        }
        turn.tool_calls.append(call)
        turn.messages.extend(tool_exchange_messages([call]))
        turn.messages = trim_to_token_budget(turn.messages, turn.budget)
        return result

    async def _persist_assistant(self, conversation_id: str, turn: _Turn, status: str) -> None:
        await self.repo.add_message(conversation_id, role="assistant", content=turn.answer, tool_calls=turn.tool_calls)
        chat_messages_total.labels(status=status).inc()
