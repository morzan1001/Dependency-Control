"""K11: oversized CBOM payloads are rejected with 413."""

from typing import Any

import pytest
from fastapi import HTTPException, Request

from app.api.v1.endpoints.cbom_ingest import _enforce_body_size_limit
from app.core.constants import MAX_CBOM_BODY_BYTES

_STATUS_TOO_LARGE = 413


def _declaring_request(size: int) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/ingest/cbom",
        "headers": [(b"content-length", str(size).encode())],
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def test_a_body_declaring_exactly_the_size_cap_is_accepted():
    _enforce_body_size_limit(_declaring_request(MAX_CBOM_BODY_BYTES))


def test_a_body_declaring_one_byte_over_the_size_cap_is_413():
    with pytest.raises(HTTPException) as exc:
        _enforce_body_size_limit(_declaring_request(MAX_CBOM_BODY_BYTES + 1))

    assert exc.value.status_code == _STATUS_TOO_LARGE
