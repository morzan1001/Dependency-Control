"""Chat service — orchestrates Ollama, tools, and SSE streaming."""

import json
import logging
import time
from typing import Any, AsyncIterator, Dict, List, Optional

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
from app.services.chat.context import build_messages, build_tool_result_message, trim_to_token_budget
from app.services.chat.ollama_client import OllamaClient
from app.services.chat.tools import ChatToolRegistry

logger = logging.getLogger(__name__)


class ChatService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.repo = ChatRepository(db)
        self.ollama = OllamaClient()
        self.tools = ChatToolRegistry()

    async def create_conversation(self, user: User, title: Optional[str] = None) -> Dict[str, Any]:
        chat_conversations_created_total.inc()
        return await self.repo.create_conversation(
            user_id=str(user.id),
            title=title or "New Conversation",
        )

    async def list_conversations(self, user: User) -> List[Dict[str, Any]]:
        return await self.repo.list_conversations(user_id=str(user.id))

    async def get_conversation(self, conversation_id: str, user: User) -> Optional[Dict[str, Any]]:
        return await self.repo.get_conversation(conversation_id, user_id=str(user.id))

    async def get_messages(self, conversation_id: str, user: User) -> List[Dict[str, Any]]:
        conv = await self.repo.get_conversation(conversation_id, user_id=str(user.id))
        if not conv:
            return []
        return await self.repo.get_messages(conversation_id)

    async def delete_conversation(self, conversation_id: str, user: User) -> bool:
        return await self.repo.delete_conversation(conversation_id, user_id=str(user.id))

    async def send_message(
        self,
        conversation_id: str,
        user: User,
        content: str,
        images: Optional[List[str]] = None,
    ) -> AsyncIterator[str]:
        """
        Process a user message and stream the response as SSE events.

        Yields SSE-formatted strings:
        - data: {"type": "token", "content": "..."}
        - data: {"type": "tool_call_start", "tool_name": "..."}
        - data: {"type": "tool_call_end", "tool_name": "...", "result": {...}}
        - data: {"type": "done"}
        - data: {"type": "error", "message": "..."}
        """
        start_time = time.time()
        first_token_recorded = False
        total_tool_calls = 0
        full_response = ""
        all_tool_calls: List[Dict[str, Any]] = []
        assistant_saved = False
        client_notified_of_error = False

        # Save user message
        await self.repo.add_message(
            conversation_id,
            role="user",
            content=content,
            images=images or [],
        )

        # Auto-generate title from first message
        conv = await self.repo.get_conversation(conversation_id, user_id=str(user.id))
        if conv and conv.get("message_count", 0) == 1:
            title = content[:80] + ("..." if len(content) > 80 else "")
            await self.repo.update_conversation_title(conversation_id, str(user.id), title)

        # Load history
        history = await self.repo.get_recent_messages(
            conversation_id, limit=settings.CHAT_MAX_HISTORY_MESSAGES
        )

        # Build context
        available_tools = self.tools.get_available_tool_definitions(user.permissions)
        messages = build_messages(history, content, images or [], len(available_tools))

        try:
            # Ollama interaction loop (tool calls may require multiple rounds).
            # Admin can tune this via SystemSettings.chat_max_tool_rounds at
            # runtime; otherwise the startup default from config.py applies.
            system_doc = await self.db["system_settings"].find_one({"_id": "current"})
            max_rounds = (
                (system_doc or {}).get("chat_max_tool_rounds")
                or settings.CHAT_MAX_TOOL_ROUNDS
            )
            rounds_used = 0
            for _ in range(max_rounds):
                rounds_used += 1
                round_tool_calls = 0
                async for chunk in self.ollama.chat_stream(messages, tools=available_tools):
                    chunk_type = chunk["type"]

                    if chunk_type == "token":
                        if not first_token_recorded:
                            chat_first_token_seconds.observe(time.time() - start_time)
                            first_token_recorded = True
                        full_response += chunk["content"]
                        yield f"data: {json.dumps({'type': 'token', 'content': chunk['content']})}\n\n"

                    elif chunk_type == "tool_call":
                        round_tool_calls += 1
                        total_tool_calls += 1
                        fn = chunk["function"]
                        tool_name = fn.get("name", "unknown")
                        tool_args = fn.get("arguments", {})

                        yield f"data: {json.dumps({'type': 'tool_call_start', 'tool_name': tool_name})}\n\n"

                        # Execute the tool with user authorization
                        result = await self.tools.execute_tool(tool_name, tool_args, user, self.db)

                        all_tool_calls.append({
                            "tool_name": tool_name,
                            "arguments": tool_args,
                            "result": result,
                            "duration_ms": int((time.time() - start_time) * 1000),
                        })

                        yield f"data: {json.dumps({'type': 'tool_call_end', 'tool_name': tool_name, 'arguments': tool_args, 'result': result}, default=str)}\n\n"

                        # Add tool result to messages for next Ollama round
                        messages.append({"role": "assistant", "content": "", "tool_calls": [{"function": fn}]})
                        messages.append(build_tool_result_message(tool_name, result))
                        # Re-trim after appending tool-call pair to stay within token budget
                        messages = trim_to_token_budget(messages, settings.CHAT_MAX_TOKEN_BUDGET)

                    elif chunk_type == "done":
                        total_tokens = chunk.get("total_tokens", 0)
                        eval_rate = chunk.get("eval_rate", 0)
                        chat_ollama_tokens_generated_total.inc(total_tokens)
                        chat_ollama_tokens_per_second.set(eval_rate)
                        break

                    elif chunk_type == "error":
                        yield f"data: {json.dumps({'type': 'error', 'message': chunk['message']})}\n\n"
                        chat_messages_total.labels(status="error").inc()
                        client_notified_of_error = True
                        return

                # If no tool calls were made in this round, we're done
                if round_tool_calls == 0:
                    break

            # If we hit the max-rounds cap without ever producing text,
            # the model got stuck in a tool-call loop. Synthesise an honest
            # fallback message so the user sees something instead of a blank
            # turn full of tool calls.
            if not full_response and rounds_used >= max_rounds and all_tool_calls:
                fallback = (
                    "_I gathered data from "
                    f"{total_tool_calls} tool call(s) but couldn't put together a "
                    "final answer within my reasoning budget. The tool results "
                    "above contain the raw data — please ask a more specific "
                    "follow-up question and I'll try again._"
                )
                full_response = fallback
                yield f"data: {json.dumps({'type': 'token', 'content': fallback})}\n\n"
                chat_messages_total.labels(status="max_rounds_exhausted").inc()

            # Save assistant response (happy path)
            await self.repo.add_message(
                conversation_id,
                role="assistant",
                content=full_response,
                tool_calls=all_tool_calls,
                token_count=0,
            )
            assistant_saved = True

            # Record metrics
            duration = time.time() - start_time
            chat_response_duration_seconds.observe(duration)
            chat_tool_calls_per_message.observe(total_tool_calls)
            chat_messages_total.labels(status="success").inc()

            yield f"data: {json.dumps({'type': 'done'})}\n\n"

        finally:
            if not assistant_saved:
                if full_response or all_tool_calls:
                    # Partial content was streamed — persist it with an interrupted marker
                    # regardless of whether an error was also notified, so the UI stays
                    # consistent on reload.
                    interrupted_content = (
                        full_response + "\n\n_[stream interrupted]_"
                        if full_response
                        else "_[stream interrupted]_"
                    )
                    await self.repo.add_message(
                        conversation_id,
                        role="assistant",
                        content=interrupted_content,
                        tool_calls=all_tool_calls,
                        token_count=0,
                    )
                    chat_messages_total.labels(status="interrupted").inc()
                elif not client_notified_of_error:
                    # Nothing streamed and no error event sent to client — save a minimal
                    # marker so the conversation doesn't have a dangling user turn.
                    await self.repo.add_message(
                        conversation_id,
                        role="assistant",
                        content="_[stream interrupted before any response]_",
                        tool_calls=[],
                        token_count=0,
                    )
                    chat_messages_total.labels(status="interrupted").inc()
                # else: error was already delivered to client and nothing was streamed
                # — nothing to save; the client decides how to handle the error.
