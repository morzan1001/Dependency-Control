"""Async HTTP client for Ollama REST API with streaming support."""

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx

from app.core.config import settings
from app.core.metrics import chat_ollama_queue_depth, chat_ollama_requests_total

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self) -> None:
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.OLLAMA_TIMEOUT_SECONDS

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a chat completion, yielding token / tool_call / done / error dicts keyed by "type"."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {
                "num_ctx": settings.OLLAMA_NUM_CTX,
            },
        }
        if tools:
            payload["tools"] = tools

        chat_ollama_queue_depth.inc()

        try:
            async with (
                httpx.AsyncClient(timeout=httpx.Timeout(self.timeout)) as client,
                client.stream(
                    "POST",
                    f"{self.base_url}/api/chat",
                    json=payload,
                ) as response,
            ):
                if response.status_code != 200:
                    body = await response.aread()
                    chat_ollama_requests_total.labels(status="error").inc()
                    yield {
                        "type": "error",
                        "message": f"Ollama returned {response.status_code}: {body.decode(errors='replace')}",
                    }
                    return

                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Once the 200 is sent, Ollama reports a failed runner as an error line.
                    if "error" in chunk:
                        chat_ollama_requests_total.labels(status="error").inc()
                        yield {"type": "error", "message": f"Ollama error: {chunk['error']}"}
                        return

                    # The done chunk can carry the last text and a tool call the parser held back.
                    message = chunk.get("message", {})
                    for tc in message.get("tool_calls") or []:
                        yield {"type": "tool_call", "function": tc.get("function", {})}
                    if content := message.get("content", ""):
                        yield {"type": "token", "content": content}

                    if chunk.get("done", False):
                        chat_ollama_requests_total.labels(status="success").inc()
                        yield {
                            "type": "done",
                            "total_tokens": chunk.get("eval_count", 0),
                            "eval_rate": chunk.get("eval_count", 0) / max(chunk.get("eval_duration", 1) / 1e9, 0.001),
                        }
                        return

                chat_ollama_requests_total.labels(status="error").inc()
                yield {"type": "error", "message": "Ollama stream ended before the answer was complete"}

        except httpx.TimeoutException:
            chat_ollama_requests_total.labels(status="timeout").inc()
            yield {"type": "error", "message": "Ollama request timed out"}
        except httpx.HTTPError as exc:
            logger.warning("Ollama request failed: %s: %s", type(exc).__name__, exc)
            chat_ollama_requests_total.labels(status="error").inc()
            yield {"type": "error", "message": "Connection to Ollama failed"}
        finally:
            chat_ollama_queue_depth.dec()
