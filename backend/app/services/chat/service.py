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
from app.services.chat.context import build_messages, build_tool_result_message
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

        # Ollama interaction loop (tool calls may require multiple rounds)
        max_rounds = 10
        for round_num in range(max_rounds):
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

                elif chunk_type == "done":
                    total_tokens = chunk.get("total_tokens", 0)
                    eval_rate = chunk.get("eval_rate", 0)
                    chat_ollama_tokens_generated_total.inc(total_tokens)
                    chat_ollama_tokens_per_second.set(eval_rate)
                    break

                elif chunk_type == "error":
                    yield f"data: {json.dumps({'type': 'error', 'message': chunk['message']})}\n\n"
                    chat_messages_total.labels(status="error").inc()
                    return

            # If no tool calls were made in this round, we're done
            if round_tool_calls == 0:
                break

        # Save assistant response
        await self.repo.add_message(
            conversation_id,
            role="assistant",
            content=full_response,
            tool_calls=all_tool_calls,
            token_count=0,
        )

        # Record metrics
        duration = time.time() - start_time
        chat_response_duration_seconds.observe(duration)
        chat_tool_calls_per_message.observe(total_tool_calls)
        chat_messages_total.labels(status="success").inc()

        yield f"data: {json.dumps({'type': 'done'})}\n\n"
