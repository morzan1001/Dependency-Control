"""Tests for InstrumentedAsyncClient verb delegation and request metrics."""

import asyncio

import httpx
import pytest

from app.core import http_utils
from app.core.http_utils import InstrumentedAsyncClient
from app.core.metrics import (
    external_api_duration_seconds,
    external_api_errors_total,
    external_api_rate_limit_hits_total,
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


@pytest.mark.asyncio
async def test_stream_yields_the_open_response_and_records_request_metrics():
    service = "MetricStream"
    req_before = _counter_value(external_api_requests_total, service)
    transport = httpx.MockTransport(lambda request: httpx.Response(202, content=b"accepted"))

    async with (
        InstrumentedAsyncClient(service, transport=transport) as client,
        client.stream("POST", "https://example.test/x", content=b"{}") as response,
    ):
        assert response.status_code == 202
        assert response.request.content == b"{}"
        assert await response.aread() == b"accepted"

    assert _counter_value(external_api_requests_total, service) == req_before + 1


@pytest.mark.asyncio
async def test_stream_error_records_error_metric_and_reraises():
    service = "MetricStreamError"
    err_before = _counter_value(external_api_errors_total, service)

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    async with InstrumentedAsyncClient(service, transport=httpx.MockTransport(refuse)) as client:
        with pytest.raises(httpx.ConnectError):
            async with client.stream("POST", "https://example.test/x"):
                pass

    assert _counter_value(external_api_errors_total, service) == err_before + 1


@pytest.mark.asyncio
async def test_stream_raises_when_not_started():
    with pytest.raises(RuntimeError):
        async with InstrumentedAsyncClient("StreamNotStarted").stream("GET", "https://example.test"):
            pass


def _scripted(outcomes: list[int | Exception], seen: list[str]) -> httpx.MockTransport:
    """Answers each request with the next status code or raises the next transport error."""

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        outcome = outcomes[min(len(seen), len(outcomes)) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        headers = {"Retry-After": "3"} if outcome == 503 else {}
        return httpx.Response(outcome, headers=headers)

    return httpx.MockTransport(handle)


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    slept: list[float] = []

    async def _record(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", _record)
    return slept


class TestSendWithBackoff:
    @pytest.mark.asyncio
    async def test_429_and_5xx_are_retried_until_the_answer(self, sleeps):
        service = "BackoffRetry"
        hits_before = _counter_value(external_api_rate_limit_hits_total, service)
        seen: list[str] = []

        async with InstrumentedAsyncClient(service, transport=_scripted([429, 500, 200], seen)) as client:
            response = await client.send_with_backoff("POST", "https://example.test", attempts=4, base_delay=2.0)

        assert response.status_code == 200
        assert seen == ["POST"] * 3
        assert sleeps == [2.0, 4.0]
        assert _counter_value(external_api_rate_limit_hits_total, service) == hits_before + 1

    @pytest.mark.asyncio
    async def test_attempts_counts_every_try_and_the_last_answer_is_returned_without_a_sleep(self, sleeps):
        seen: list[str] = []

        async with InstrumentedAsyncClient("BackoffExhausted", transport=_scripted([429], seen)) as client:
            response = await client.send_with_backoff("GET", "https://example.test", attempts=3, base_delay=1.0)

        assert response.status_code == 429
        assert len(seen) == 3
        assert sleeps == [1.0, 2.0]

    @pytest.mark.asyncio
    async def test_retry_after_replaces_the_exponential_delay(self, sleeps):
        async with InstrumentedAsyncClient("BackoffRetryAfter", transport=_scripted([503, 200], [])) as client:
            response = await client.send_with_backoff("GET", "https://example.test", attempts=2, base_delay=10.0)

        assert response.status_code == 200
        assert sleeps == [3.0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [400, 404, 403])
    async def test_other_answers_are_returned_at_once(self, sleeps, status):
        seen: list[str] = []

        async with InstrumentedAsyncClient("BackoffFinal", transport=_scripted([status], seen)) as client:
            response = await client.send_with_backoff("GET", "https://example.test", attempts=4, base_delay=1.0)

        assert response.status_code == status
        assert len(seen) == 1
        assert sleeps == []

    @pytest.mark.asyncio
    async def test_a_transport_error_is_retried_then_reraised(self, sleeps):
        seen: list[str] = []
        transport = _scripted([httpx.ConnectError("refused"), httpx.ReadTimeout("slow")], seen)

        async with InstrumentedAsyncClient("BackoffTransport", transport=transport) as client:
            with pytest.raises(httpx.ReadTimeout):
                await client.send_with_backoff("GET", "https://example.test", attempts=3, base_delay=1.0)

        assert len(seen) == 3
        assert sleeps == [1.0, 2.0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("seconds_left", "tries"), [(-1.0, 1), (1.5, 2), (100.0, 4)])
    async def test_no_retry_is_started_that_would_begin_past_the_deadline(self, sleeps, seconds_left, tries):
        seen: list[str] = []
        deadline = asyncio.get_running_loop().time() + seconds_left

        async with InstrumentedAsyncClient("BackoffDeadline", transport=_scripted([429], seen)) as client:
            response = await client.send_with_backoff(
                "GET", "https://example.test", attempts=4, base_delay=1.0, deadline=deadline
            )

        # The recorded sleeps take no time, so only the backoff delays count against the deadline.
        assert response.status_code == 429
        assert len(seen) == tries
        assert sleeps == [1.0, 2.0, 4.0][: tries - 1]
