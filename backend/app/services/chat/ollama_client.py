"""Async HTTP client for Ollama REST API with streaming support."""

import json
import logging
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.core.config import settings
from app.core.metrics import chat_ollama_requests_total, chat_ollama_queue_depth

logger = logging.getLogger(__name__)

# Track concurrent requests
_active_requests = 0


class OllamaClient:
    def __init__(
        self,
        base_url: str = "",
        model: str = "",
        timeout: int = 0,
    ):
        self.base_url = base_url or settings.OLLAMA_BASE_URL
        self.model = model or settings.OLLAMA_MODEL
        self.timeout = timeout or settings.OLLAMA_TIMEOUT_SECONDS

    async def chat_stream(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Stream a chat completion from Ollama.

        Yields dicts with keys:
        - {"type": "token", "content": "..."} for text tokens
        - {"type": "tool_call", "function": {"name": "...", "arguments": {...}}} for tool calls
        - {"type": "done", "total_tokens": N, "eval_rate": N} on completion
        - {"type": "error", "message": "..."} on failure
        """
        global _active_requests

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {
                "num_ctx": settings.OLLAMA_NUM_CTX,
            },
        }
        if tools:
            payload["tools"] = tools

        _active_requests += 1
        chat_ollama_queue_depth.set(_active_requests)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout)) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/api/chat",
                    json=payload,
                ) as response:
                    if response.status_code != 200:
                        body = await response.aread()
                        chat_ollama_requests_total.labels(status="error").inc()
                        yield {"type": "error", "message": f"Ollama returned {response.status_code}: {body.decode()}"}
                        return

                    chat_ollama_requests_total.labels(status="success").inc()

                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if chunk.get("done", False):
                            yield {
                                "type": "done",
                                "total_tokens": chunk.get("eval_count", 0),
                                "eval_rate": chunk.get("eval_count", 0) / max(chunk.get("eval_duration", 1) / 1e9, 0.001),
                            }
                            return

                        message = chunk.get("message", {})

                        # Tool calls
                        if message.get("tool_calls"):
                            for tc in message["tool_calls"]:
                                yield {
                                    "type": "tool_call",
                                    "function": tc.get("function", {}),
                                }

                        # Text content
                        content = message.get("content", "")
                        if content:
                            yield {"type": "token", "content": content}

        except httpx.TimeoutException:
            chat_ollama_requests_total.labels(status="timeout").inc()
            yield {"type": "error", "message": "Ollama request timed out"}
        except httpx.ConnectError:
            chat_ollama_requests_total.labels(status="error").inc()
            yield {"type": "error", "message": "Could not connect to Ollama"}
        finally:
            _active_requests -= 1
            chat_ollama_queue_depth.set(_active_requests)

    async def health_check(self) -> bool:
        """Check if Ollama is reachable and the model is loaded."""
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5)) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code != 200:
                    return False
                data = resp.json()
                model_names = [m.get("name", "") for m in data.get("models", [])]
                return any(self.model in name for name in model_names)
        except Exception:
            return False
