"""The Ollama queue-depth gauge counts streaming requests while they are in flight."""

import httpx
import pytest
from prometheus_client import REGISTRY

from app.services.chat.ollama_client import OllamaClient

_STREAM = b'{"message": {"content": "hi"}}\n{"done": true, "eval_count": 3, "eval_duration": 1000000000}\n'


def _depth() -> float:
    return REGISTRY.get_sample_value("dc_chat_ollama_queue_depth")


def _route_ollama_to(monkeypatch, handler) -> None:
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.asyncio
async def test_a_streaming_request_is_counted_until_it_finishes(monkeypatch):
    _route_ollama_to(monkeypatch, lambda _request: httpx.Response(200, content=_STREAM))
    before = _depth()
    stream = OllamaClient(base_url="http://ollama.test", model="m", timeout=5).chat_stream([])

    first = await anext(stream)
    assert first == {"type": "token", "content": "hi"}
    assert _depth() == before + 1

    assert [event["type"] async for event in stream] == ["done"]
    assert _depth() == before


@pytest.mark.asyncio
async def test_a_failed_connection_releases_its_slot(monkeypatch):
    def refuse(request):
        raise httpx.ConnectError("refused", request=request)

    _route_ollama_to(monkeypatch, refuse)
    before = _depth()

    events = [event async for event in OllamaClient(base_url="http://ollama.test", model="m").chat_stream([])]

    assert events == [{"type": "error", "message": "Could not connect to Ollama"}]
    assert _depth() == before
