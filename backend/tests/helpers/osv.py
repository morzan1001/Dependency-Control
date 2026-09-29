"""The OSV analyzer's real HTTP client, answered in-process through httpx.MockTransport."""

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from app.core.http_utils import InstrumentedAsyncClient
from app.services.analyzers.osv import OSVAnalyzer


def serve_osv(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> list[httpx.Request]:
    """Answer every OSV request with ``handler``, backoff delays zeroed; returns the requests in arrival order."""
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    transport = httpx.MockTransport(_record)
    monkeypatch.setattr(OSVAnalyzer, "retry_base_delay", 0.0)
    monkeypatch.setattr(
        "app.services.analyzers.osv.InstrumentedAsyncClient",
        lambda service, **kwargs: InstrumentedAsyncClient(service, transport=transport, **kwargs),
    )
    return seen


def osv_cache(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """An in-memory cache_service for the OSV analyzer; the returned dict is its store."""
    store: dict[str, Any] = {}

    async def _mget(keys: list[str]) -> dict[str, Any]:
        return {key: store.get(key) for key in keys}

    async def _mset(mapping: dict[str, Any], ttl_seconds: int | None = None) -> bool:
        store.update(mapping)
        return True

    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mget", _mget)
    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mset", _mset)
    return store


def batch_queries(requests: list[httpx.Request]) -> list[dict[str, Any]]:
    """Every querybatch query among ``requests``, in the order they were sent."""
    return [
        query for request in requests if request.method == "POST" for query in json.loads(request.content)["queries"]
    ]


def vuln_ids_fetched(requests: list[httpx.Request]) -> list[str]:
    return [request.url.path.rsplit("/", 1)[-1] for request in requests if request.method == "GET"]
