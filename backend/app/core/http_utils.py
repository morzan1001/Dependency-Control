"""HTTP client helpers for shared error handling and retry logic."""

import asyncio
import time
from collections.abc import AsyncIterator
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
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> None:
        self.service_name = service_name
        self._client: httpx.AsyncClient | None = None
        self._timeout = timeout
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

    def _record_success(self, duration: float) -> None:
        external_api_duration_seconds.labels(service=self.service_name).observe(duration)

    def _record_error(self) -> None:
        external_api_errors_total.labels(service=self.service_name).inc()

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start_time = time.time()
        self._record_request()
        try:
            response = await self._client.request(method, url, **kwargs)
            self._record_success(time.time() - start_time)
            return response
        except Exception:
            self._record_error()
            raise

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
        """Retries 429, 5xx and transport errors; returns the last answer or re-raises the last error."""
        loop = asyncio.get_running_loop()
        outcome: httpx.Response | httpx.TransportError
        for attempt in range(attempts):
            try:
                outcome = await self.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                outcome = exc
            if isinstance(outcome, httpx.Response):
                if outcome.status_code == 429:
                    external_api_rate_limit_hits_total.labels(service=self.service_name).inc()
                elif outcome.status_code < 500:
                    return outcome
            delay = _retry_after_seconds(outcome) or base_delay * 2**attempt
            if attempt == attempts - 1 or (deadline is not None and loop.time() + delay >= deadline):
                break
            await asyncio.sleep(delay)
        if isinstance(outcome, httpx.TransportError):
            raise outcome
        return outcome

    @asynccontextmanager
    async def stream(self, method: str, url: str, **kwargs: Any) -> AsyncIterator[httpx.Response]:
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start_time = time.time()
        self._record_request()
        try:
            async with self._client.stream(method, url, **kwargs) as response:
                self._record_success(time.time() - start_time)
                yield response
        except Exception:
            self._record_error()
            raise

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)
