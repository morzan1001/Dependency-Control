"""HTTP client helpers for shared error handling and retry logic."""

import time
from typing import Any, Optional

import httpx

from app.core.metrics import (
    external_api_duration_seconds,
    external_api_errors_total,
    external_api_requests_total,
)


class InstrumentedAsyncClient:
    """httpx.AsyncClient wrapper that records request/duration/error Prometheus metrics."""

    def __init__(
        self,
        service_name: str,
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> None:
        self.service_name = service_name
        self._client: Optional[httpx.AsyncClient] = None
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

    async def __aenter__(self) -> "InstrumentedAsyncClient":
        await self.start()
        return self

    async def __aexit__(
        self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]
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

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)
