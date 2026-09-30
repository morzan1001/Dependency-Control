import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Any

import httpx
from typing_extensions import Self

from app.core.metrics import (
    external_api_duration_seconds,
    external_api_errors_total,
    external_api_rate_limit_hits_total,
    external_api_requests_total,
)

logger = logging.getLogger(__name__)

# httpx logs every request URL at INFO, and webhook URLs carry their credential in the path or query.
logging.getLogger("httpx").setLevel(logging.WARNING)

# Loading the CA bundle takes milliseconds of blocking CPU, so every client shares one context.
SSL_CONTEXT = httpx.create_ssl_context()

_MAX_RETRY_AFTER_SECONDS = 60.0


def _retry_after_seconds(outcome: httpx.Response | httpx.TransportError) -> float | None:
    if not isinstance(outcome, httpx.Response):
        return None
    try:
        return min(float(outcome.headers["Retry-After"]), _MAX_RETRY_AFTER_SECONDS)
    except (KeyError, ValueError):
        return None


class InstrumentedAsyncClient:
    """httpx.AsyncClient wrapper that records request/duration/error Prometheus metrics."""

    def __init__(
        self,
        service_name: str,
        timeout: float | httpx.Timeout = 30.0,
        **kwargs: Any,
    ) -> None:
        self.service_name = service_name
        self._client: httpx.AsyncClient | None = None
        self._timeout = timeout
        if "transport" not in kwargs:
            kwargs.setdefault("verify", SSL_CONTEXT)
        self._kwargs = kwargs
        self._NOT_STARTED_MSG = "Client not started. Use 'async with' or call start()."

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout, **self._kwargs)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
    ) -> None:
        await self.close()

    def _record_request(self) -> None:
        external_api_requests_total.labels(service=self.service_name).inc()

    def _record_duration(self, start: float) -> None:
        external_api_duration_seconds.labels(service=self.service_name).observe(time.monotonic() - start)

    def _record_error(self) -> None:
        external_api_errors_total.labels(service=self.service_name).inc()

    def _record_answer(self, response: httpx.Response) -> None:
        status, headers = response.status_code, response.headers
        # A 404 or another 4xx is an expected negative answer, not an upstream failure.
        if status >= 500 or status in (401, 403, 429):
            self._record_error()
        # GitHub answers an exhausted primary or secondary quota with 403 as well as 429.
        if status == 429 or (
            status == 403 and ("Retry-After" in headers or headers.get("X-RateLimit-Remaining") == "0")
        ):
            external_api_rate_limit_hits_total.labels(service=self.service_name).inc()

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start = time.monotonic()
        self._record_request()
        try:
            response = await self._client.request(method, url, **kwargs)
        except Exception:
            self._record_error()
            raise
        finally:
            self._record_duration(start)
        self._record_answer(response)
        return response

    async def send_with_backoff(
        self,
        method: str,
        url: str,
        *,
        attempts: int,
        base_delay: float,
        deadline: float | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Retries 429, 5xx and non-timeout transport errors; returns the last answer or re-raises the last error."""
        loop = asyncio.get_running_loop()
        outcome: httpx.Response | httpx.TransportError
        for attempt in range(attempts):
            try:
                outcome = await self.request(method, url, **kwargs)
            except httpx.TimeoutException:
                # A timed-out try already spent the whole timeout; repeating it multiplies a hanging upstream's cost.
                raise
            except httpx.TransportError as exc:
                outcome = exc
            if isinstance(outcome, httpx.Response) and outcome.status_code != 429 and outcome.status_code < 500:
                return outcome
            delay = d if (d := _retry_after_seconds(outcome)) is not None else base_delay * 2**attempt
            if attempt == attempts - 1 or (deadline is not None and loop.time() + delay >= deadline):
                break
            cause = outcome.status_code if isinstance(outcome, httpx.Response) else type(outcome).__name__
            logger.debug(f"{self.service_name} {method} failed with {cause}; retrying in {delay:.1f}s")
            await asyncio.sleep(delay)
        if isinstance(outcome, httpx.TransportError):
            raise outcome
        return outcome

    @asynccontextmanager
    async def stream(self, method: str, url: str, **kwargs: Any) -> AsyncIterator[httpx.Response]:
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start = time.monotonic()
        self._record_request()
        try:
            async with self._client.stream(method, url, **kwargs) as response:
                self._record_answer(response)
                yield response
        except Exception:
            self._record_error()
            raise
        finally:
            self._record_duration(start)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)


async def gather_bounded[T, R](
    items: Iterable[T], worker: Callable[[T], Awaitable[R]], limit: int
) -> list[R | BaseException]:
    """Run ``worker`` over ``items`` with at most ``limit`` in flight; a failure stays in its item's slot."""
    slots = list(items)
    results: list[Any] = [None] * len(slots)
    pending = iter(enumerate(slots))

    async def runner() -> None:
        this = asyncio.current_task()
        assert this is not None
        for index, item in pending:
            try:
                results[index] = await worker(item)
            except asyncio.CancelledError as exc:
                # A worker's own cancellation fills its slot; cancelling the run must still stop it.
                if this.cancelling():
                    raise
                results[index] = exc
            except Exception as exc:
                results[index] = exc

    await asyncio.gather(*(runner() for _ in range(min(limit, len(slots)))))
    return results
