"""Body-size guard: declared size rejected up front, chunked uploads rejected while reading."""

from typing import Any

import pytest
from fastapi import HTTPException, Request

from app.api.v1.helpers.body_limit import enforce_declared_body_size, read_body_within_limit

_LIMIT = 100
_UNDER_LIMIT = 50
_OVER_LIMIT = _LIMIT + 1
_CHUNK_SIZE = 60
_HALF_LIMIT_CHUNK = _LIMIT // 2
_STATUS_BAD_REQUEST = 400
_STATUS_TOO_LARGE = 413


def _request(headers: dict[str, str], chunks: list[bytes] | None = None) -> Request:
    remaining = chunks if chunks is not None else []
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/analyze",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }

    async def receive() -> dict[str, Any]:
        if remaining:
            chunk = remaining.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(remaining)}
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def test_declared_size_within_limit_passes():
    guard = enforce_declared_body_size(_LIMIT)
    guard(_request({"content-length": str(_UNDER_LIMIT)}))


def test_declared_size_exactly_at_the_limit_passes():
    guard = enforce_declared_body_size(_LIMIT)
    guard(_request({"content-length": str(_LIMIT)}))


def test_declared_size_over_limit_is_413():
    guard = enforce_declared_body_size(_LIMIT)
    with pytest.raises(HTTPException) as exc:
        guard(_request({"content-length": str(_OVER_LIMIT)}))
    assert exc.value.status_code == _STATUS_TOO_LARGE
    assert str(_OVER_LIMIT) in exc.value.detail


def test_unparseable_content_length_is_400():
    guard = enforce_declared_body_size(_LIMIT)
    with pytest.raises(HTTPException) as exc:
        guard(_request({"content-length": "not-a-number"}))
    assert exc.value.status_code == _STATUS_BAD_REQUEST


def test_missing_content_length_passes_the_declared_check():
    guard = enforce_declared_body_size(_LIMIT)
    guard(_request({"transfer-encoding": "chunked"}))


@pytest.mark.asyncio
async def test_chunked_body_within_limit_is_returned_whole():
    request = _request({"transfer-encoding": "chunked"}, chunks=[b"abc", b"def"])
    assert await read_body_within_limit(request, _LIMIT) == b"abcdef"


@pytest.mark.asyncio
async def test_chunked_body_exactly_at_the_limit_is_returned_whole():
    chunks = [b"a" * _HALF_LIMIT_CHUNK, b"b" * _HALF_LIMIT_CHUNK]
    request = _request({"transfer-encoding": "chunked"}, chunks=list(chunks))
    assert await read_body_within_limit(request, _LIMIT) == b"".join(chunks)


@pytest.mark.asyncio
async def test_chunked_body_over_limit_is_413_without_buffering_everything():
    unread = [b"a" * _CHUNK_SIZE, b"b" * _CHUNK_SIZE, b"c" * _CHUNK_SIZE]
    request = _request({"transfer-encoding": "chunked"}, chunks=unread)

    with pytest.raises(HTTPException) as exc:
        await read_body_within_limit(request, _LIMIT)

    assert exc.value.status_code == _STATUS_TOO_LARGE
    assert str(_LIMIT) in exc.value.detail
    assert len(unread) == 1, "the reader kept pulling chunks after the ceiling was crossed"
