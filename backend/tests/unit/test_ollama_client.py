"""OllamaClient turns Ollama's NDJSON chat stream into token / tool_call / done / error events."""

import json

import httpx
import pytest
from prometheus_client import REGISTRY

from app.core.config import settings
from app.services.chat.ollama_client import OllamaClient

_STREAM = b'{"message": {"content": "hi"}}\n{"done": true, "eval_count": 3, "eval_duration": 1000000000}\n'


def _depth() -> float:
    return REGISTRY.get_sample_value("dc_chat_ollama_queue_depth")


def _requests(status: str) -> float:
    return REGISTRY.get_sample_value("dc_chat_ollama_requests_total", {"status": status}) or 0.0


def _route_ollama_to(monkeypatch, handler) -> None:
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))


def _ndjson(*chunks: dict) -> bytes:
    return b"".join(json.dumps(c).encode() + b"\n" for c in chunks)


class _DyingStream(httpx.AsyncByteStream):
    """A response body that delivers some lines, then loses the connection the way a killed runner does."""

    def __init__(self, head: bytes, error: Exception):
        self.head = head
        self.error = error

    async def __aiter__(self):
        yield self.head
        raise self.error


async def _events(monkeypatch, handler) -> list[dict]:
    _route_ollama_to(monkeypatch, handler)
    return [event async for event in OllamaClient().chat_stream([])]


@pytest.mark.asyncio
async def test_a_streaming_request_is_counted_until_it_finishes(monkeypatch):
    _route_ollama_to(monkeypatch, lambda _request: httpx.Response(200, content=_STREAM))
    before = _depth()
    stream = OllamaClient().chat_stream([])

    first = await anext(stream)
    assert first == {"type": "token", "content": "hi"}
    assert _depth() == before + 1

    assert [event["type"] async for event in stream] == ["done"]
    assert _depth() == before


@pytest.mark.asyncio
async def test_a_failed_connection_releases_its_slot(monkeypatch):
    def refuse(request):
        raise httpx.ConnectError("refused", request=request)

    before = _depth()

    events = await _events(monkeypatch, refuse)

    assert events == [{"type": "error", "message": "Connection to Ollama failed"}]
    assert _depth() == before


@pytest.mark.asyncio
async def test_tool_calls_and_text_on_the_done_chunk_are_delivered_before_done(monkeypatch):
    body = _ndjson(
        {"message": {"role": "assistant", "content": "Let me check. "}, "done": False},
        {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "list_projects", "arguments": {}}}],
            },
            "done": True,
            "done_reason": "stop",
            "eval_count": 12,
            "eval_duration": 1_000_000_000,
        },
    )

    events = await _events(monkeypatch, lambda _request: httpx.Response(200, content=body))

    assert [e["type"] for e in events] == ["token", "tool_call", "done"]
    assert events[1]["function"] == {"name": "list_projects", "arguments": {}}


@pytest.mark.asyncio
async def test_an_error_line_mid_stream_fails_the_stream_and_is_not_counted_as_success(monkeypatch):
    body = _ndjson(
        {"message": {"role": "assistant", "content": "Project Alpha has"}, "done": False},
        {"error": "llama runner process has terminated"},
    )
    successes, errors = _requests("success"), _requests("error")

    events = await _events(monkeypatch, lambda _request: httpx.Response(200, content=body))

    assert events == [
        {"type": "token", "content": "Project Alpha has"},
        {"type": "error", "message": "Ollama error: llama runner process has terminated"},
    ]
    assert _requests("success") == successes
    assert _requests("error") == errors + 1


@pytest.mark.asyncio
async def test_a_connection_lost_mid_stream_emits_an_error_event(monkeypatch):
    head = _ndjson({"message": {"role": "assistant", "content": "Partial"}, "done": False})
    lost = httpx.RemoteProtocolError("peer closed connection without sending complete message body")
    successes, errors = _requests("success"), _requests("error")

    events = await _events(monkeypatch, lambda _request: httpx.Response(200, stream=_DyingStream(head, lost)))

    assert events == [
        {"type": "token", "content": "Partial"},
        {"type": "error", "message": "Connection to Ollama failed"},
    ]
    assert _requests("success") == successes
    assert _requests("error") == errors + 1


@pytest.mark.asyncio
async def test_a_stream_that_ends_without_done_is_an_error(monkeypatch):
    body = _ndjson({"message": {"role": "assistant", "content": "Cut"}, "done": False})
    successes = _requests("success")

    events = await _events(monkeypatch, lambda _request: httpx.Response(200, content=body))

    assert [e["type"] for e in events] == ["token", "error"]
    assert _requests("success") == successes


@pytest.mark.asyncio
async def test_only_a_completed_stream_counts_as_success(monkeypatch):
    successes = _requests("success")

    await _events(monkeypatch, lambda _request: httpx.Response(200, content=_STREAM))

    assert _requests("success") == successes + 1


@pytest.mark.asyncio
async def test_the_client_reads_endpoint_model_and_timeout_from_settings(monkeypatch):
    monkeypatch.setattr(settings, "OLLAMA_BASE_URL", "http://ollama.test:1234")
    monkeypatch.setattr(settings, "OLLAMA_MODEL", "gemma-test")
    seen: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["model"] = json.loads(request.content)["model"]
        return httpx.Response(200, content=_STREAM)

    await _events(monkeypatch, capture)

    assert seen == {"url": "http://ollama.test:1234/api/chat", "model": "gemma-test"}
