"""Tests for InstrumentedAsyncClient verb delegation and request metrics."""

import asyncio

import httpx
import pytest

from app.core import http_utils
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import (
    external_api_duration_seconds,
    external_api_errors_total,
    external_api_requests_total,
)


class _FakeHttpxClient:
    """Records request() calls and returns a canned response (or raises)."""

    def __init__(self, exc: Exception | None = None, delay: float = 0.0) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self._exc = exc
        self._delay = delay

    async def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._exc is not None:
            raise self._exc
        return httpx.Response(200, request=httpx.Request(method, url))


def _counter_value(counter, service: str) -> float:
    return counter.labels(service=service)._value.get()


def _histogram_sum(histogram, service: str) -> float:
    return histogram.labels(service=service)._sum.get()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verb, expected_method",
    [("get", "GET"), ("post", "POST"), ("put", "PUT"), ("patch", "PATCH"), ("delete", "DELETE")],
)
async def test_verbs_delegate_to_request(verb, expected_method):
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
    for verb in ("get", "post", "put", "patch", "delete", "request"):
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


@pytest.mark.asyncio
async def test_started_client_carries_the_configured_timeout():
    default = InstrumentedAsyncClient("TimeoutDefault")
    await default.start()
    try:
        # httpx's own default is 5s, so an unset timeout is indistinguishable from a set one
        # unless we pin the value the wrapper is supposed to install.
        assert default._client.timeout == httpx.Timeout(30.0)
    finally:
        await default.close()

    explicit = InstrumentedAsyncClient("TimeoutExplicit", timeout=120.0)
    await explicit.start()
    try:
        assert explicit._client.timeout == httpx.Timeout(120.0)
    finally:
        await explicit.close()


@pytest.mark.asyncio
async def test_success_observes_the_elapsed_duration_in_the_histogram():
    service = "MetricDuration"
    before = _histogram_sum(external_api_duration_seconds, service)
    client = InstrumentedAsyncClient(service)
    client._client = _FakeHttpxClient(delay=0.05)  # type: ignore[assignment]

    await client.get("https://example.test")

    assert _histogram_sum(external_api_duration_seconds, service) - before >= 0.04


def test_dead_helpers_removed():
    for name in (
        "HTTPRequestError",
        "safe_http_request",
        "fetch_json",
        "post_json",
        "with_http_error_handling",
    ):
        assert not hasattr(http_utils, name), f"{name} should have been removed"
