"""Tests for InstrumentedAsyncClient in app.core.http_utils.

Covers the verb-method delegation refactor (get/post/put/delete now route
through request()) and the request/success/error metric protocol.
"""

import httpx
import pytest

from app.core import http_utils
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import (
    external_api_errors_total,
    external_api_requests_total,
)


class _FakeHttpxClient:
    """Records request() calls and returns a canned response (or raises)."""

    def __init__(self, exc: Exception | None = None) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self._exc = exc

    async def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        if self._exc is not None:
            raise self._exc
        return httpx.Response(200, request=httpx.Request(method, url))


def _counter_value(counter, service: str) -> float:
    return counter.labels(service=service)._value.get()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verb, expected_method",
    [("get", "GET"), ("post", "POST"), ("put", "PUT"), ("delete", "DELETE")],
)
async def test_verbs_delegate_to_request(verb, expected_method):
    """get/post/put/delete must call the underlying client's request() with the
    correct HTTP method (proves they delegate to request() rather than calling
    client.get/post/... directly)."""
    client = InstrumentedAsyncClient("VerbTest")
    fake = _FakeHttpxClient()
    client._client = fake  # type: ignore[assignment]

    resp = await getattr(client, verb)("https://example.test/x", params={"a": 1})

    assert resp.status_code == 200
    assert len(fake.calls) == 1
    method, url, kwargs = fake.calls[0]
    assert method == expected_method
    assert url == "https://example.test/x"
    assert kwargs == {"params": {"a": 1}}


@pytest.mark.asyncio
async def test_verbs_raise_when_not_started():
    client = InstrumentedAsyncClient("NotStarted")
    for verb in ("get", "post", "put", "delete", "request"):
        with pytest.raises(RuntimeError):
            if verb == "request":
                await client.request("GET", "https://example.test")
            else:
                await getattr(client, verb)("https://example.test")


@pytest.mark.asyncio
async def test_success_records_request_metric():
    service = "MetricSuccess"
    before = _counter_value(external_api_requests_total, service)
    client = InstrumentedAsyncClient(service)
    client._client = _FakeHttpxClient()  # type: ignore[assignment]

    await client.get("https://example.test")

    assert _counter_value(external_api_requests_total, service) == before + 1


@pytest.mark.asyncio
async def test_error_records_error_metric_and_reraises():
    service = "MetricError"
    req_before = _counter_value(external_api_requests_total, service)
    err_before = _counter_value(external_api_errors_total, service)
    client = InstrumentedAsyncClient(service)
    client._client = _FakeHttpxClient(exc=httpx.ConnectError("boom"))  # type: ignore[assignment]

    with pytest.raises(httpx.ConnectError):
        await client.post("https://example.test", json={})

    assert _counter_value(external_api_requests_total, service) == req_before + 1
    assert _counter_value(external_api_errors_total, service) == err_before + 1


def test_dead_helpers_removed():
    """The unreferenced HTTP helpers were deleted; only InstrumentedAsyncClient remains."""
    for name in (
        "HTTPRequestError",
        "safe_http_request",
        "fetch_json",
        "post_json",
        "with_http_error_handling",
    ):
        assert not hasattr(http_utils, name), f"{name} should have been removed"
