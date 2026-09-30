"""Chat service — orchestrates Ollama, tools, and SSE streaming."""

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
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

logger = logging.getLogger(__name__)

# Seconds between cold-start keepalive info events; module-level so tests can patch it.
_WARMUP_SLICE_SECONDS = 10.0

_INTERRUPTED = "_[stream interrupted]_"
_EMPTY_ANSWER = "_The model returned an empty response. Please try again or rephrase the question._"


def _sse(event: str, **data: Any) -> str:
    return f"data: {json.dumps({'type': event, **data}, default=str)}\n\n"


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

    async def list_conversations(self, user: User) -> list[dict[str, Any]]:
        return await self.repo.list_conversations(user_id=str(user.id))

    async def get_conversation(self, conversation_id: str, user: User) -> dict[str, Any] | None:
        return await self.repo.get_conversation(conversation_id, user_id=str(user.id))

    async def get_messages(self, conversation_id: str) -> list[dict[str, Any]]:
        return await self.repo.get_messages(conversation_id)

    async def delete_conversation(self, conversation_id: str, user: User) -> bool:
        return await self.repo.delete_conversation(conversation_id, user_id=str(user.id))

    async def send_message(
        self,
        conversation_id: str,
        user: User,
        content: str,
        *,
        max_tool_rounds: int,
    ) -> AsyncIterator[str]:
        """Process a user message and stream the response as SSE event strings."""
        start_time = time.time()
        first_token_recorded = False
        total_tool_calls = 0
        round_tool_calls = 0
        answer = ""
        all_tool_calls: list[dict[str, Any]] = []
        assistant_saved = False
        client_notified_of_error = False

        # Load history before persisting the new message so the current turn isn't replayed twice.
        history = await self.repo.get_recent_messages(conversation_id, limit=settings.CHAT_MAX_HISTORY_MESSAGES)

        message_count = await self.repo.add_message(conversation_id, role="user", content=content)
        if message_count is None:
            yield _sse("error", message="Conversation not found")
            return
        if message_count == 1:
            title = content[:80] + ("..." if len(content) > 80 else "")
            await self.repo.update_conversation_title(conversation_id, str(user.id), title)

        available_tools = self.tools.get_available_tool_definitions(user.permissions)
        budget = message_token_budget(available_tools)
        messages = build_messages(history, content, budget)

        try:
            for _ in range(max_tool_rounds):
                round_tool_calls = 0
                answer = ""
                stream_iter = self.ollama.chat_stream(messages, tools=available_tools).__aiter__()
                while True:
                    try:
                        if not first_token_recorded and total_tool_calls == 0:
                            # Cold start can take 60-90s to load the model; emit SSE heartbeat
                            # comments so the connection and upstream proxies don't idle-timeout.
                            # shield + one persistent task keeps the fetch alive across slices,
                            # since asyncio.wait_for would cancel it and abort the load on timeout.
                            pending = asyncio.ensure_future(stream_iter.__anext__())
                            try:
                                while True:
                                    try:
                                        chunk = await asyncio.wait_for(
                                            asyncio.shield(pending),
                                            timeout=_WARMUP_SLICE_SECONDS,
                                        )
                                        break
                                    except asyncio.TimeoutError:
                                        yield ": keepalive\n\n"
                            finally:
                                # Cancel the shielded fetch if we exit before consuming the
                                # chunk (e.g. client disconnect), else it keeps pinning Ollama/GPU.
                                if not pending.done():
                                    pending.cancel()
                                    await asyncio.gather(pending, return_exceptions=True)
                        else:
                            chunk = await stream_iter.__anext__()
                    except StopAsyncIteration:
                        break

                    chunk_type = chunk["type"]

                    if chunk_type == "token":
                        if not first_token_recorded:
                            chat_first_token_seconds.observe(time.time() - start_time)
                            first_token_recorded = True
                        answer += chunk["content"]
                        yield _sse("token", content=chunk["content"])

                    elif chunk_type == "tool_call":
                        round_tool_calls += 1
                        total_tool_calls += 1
                        fn = chunk["function"]
                        tool_name = fn.get("name", "unknown")
                        tool_args = fn.get("arguments", {})

                        yield _sse("tool_call_start", tool_name=tool_name)

                        tool_start = time.monotonic()
                        result = await self.tools.execute_tool(tool_name, tool_args, user, self.db)
                        all_tool_calls.append(
                            {
                                "tool_name": tool_name,
                                "arguments": tool_args,
                                "result": result,
                                "duration_ms": int((time.monotonic() - tool_start) * 1000),
                            }
                        )

                        yield _sse("tool_call_end", tool_name=tool_name, arguments=tool_args, result=result)

                        messages.extend(tool_exchange_messages(all_tool_calls[-1:]))
                        messages = trim_to_token_budget(messages, budget)

                    elif chunk_type == "done":
                        chat_ollama_tokens_generated_total.inc(chunk.get("total_tokens", 0))
                        chat_ollama_tokens_per_second.set(chunk.get("eval_rate", 0))
                        break

                    elif chunk_type == "error":
                        yield _sse("error", message=chunk["message"])
                        client_notified_of_error = True
                        return

                if round_tool_calls == 0:
                    break

            # Only the last round's text answers the question; earlier rounds only led up to tool calls.
            status = "success"
            if round_tool_calls > 0:
                status = "max_rounds_exhausted"
                answer = (
                    "_I gathered data from "
                    f"{total_tool_calls} tool call(s) but couldn't put together a "
                    "final answer within my reasoning budget. The tool results "
                    "above contain the raw data — please ask a more specific "
                    "follow-up question and I'll try again._"
                )
            elif not answer.strip():
                status = "empty_response"
                answer = _EMPTY_ANSWER
            if status != "success":
                yield _sse("token", content=f"\n\n{answer}" if first_token_recorded else answer)

            await self._persist_assistant(conversation_id, answer, all_tool_calls, status)
            assistant_saved = True

            chat_response_duration_seconds.observe(time.time() - start_time)
            chat_tool_calls_per_message.observe(total_tool_calls)

            yield _sse("done")

        finally:
            if not assistant_saved:
                # A client disconnect cancels the response's scope; the save must still land.
                with anyio.CancelScope(shield=True):
                    await self._persist_assistant(
                        conversation_id,
                        f"{answer}\n\n{_INTERRUPTED}" if answer else _INTERRUPTED,
                        all_tool_calls,
                        "error" if client_notified_of_error else "interrupted",
                    )

    async def _persist_assistant(
        self,
        conversation_id: str,
        content: str,
        tool_calls: list[dict[str, Any]],
        status: str,
    ) -> None:
        await self.repo.add_message(conversation_id, role="assistant", content=content, tool_calls=tool_calls)
        chat_messages_total.labels(status=status).inc()
