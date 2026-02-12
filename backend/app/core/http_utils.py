"""
HTTP Utilities

Shared utilities for HTTP client operations, error handling,
and retry logic. Eliminates duplicate httpx exception handling.
"""

import logging
import time
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any, AsyncGenerator, Callable, Optional, TypeVar

import httpx

from app.core.metrics import (
    external_api_duration_seconds,
    external_api_errors_total,
    external_api_requests_total,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class HTTPRequestError(Exception):
    """Base exception for HTTP request failures."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


@asynccontextmanager
async def safe_http_request(
    service_name: str,
    operation: str,
    timeout: float = 30.0,
    suppress_errors: bool = True,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """
    Context manager for safe HTTP requests with consistent error handling.

    Usage:
        async with safe_http_request("GitHub API", "fetch advisory") as client:
            response = await client.get(url)
            # process response

    Args:
        service_name: Name of the external service (for logging)
        operation: Description of the operation (for logging)
        timeout: Request timeout in seconds
        suppress_errors: If True, log errors but don't raise. If False, raise HTTPRequestError.

    Yields:
        Configured httpx.AsyncClient
    """
    start_time = time.time()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            external_api_requests_total.labels(service=service_name).inc()
            yield client
            # Record duration on success
            duration = time.time() - start_time
            external_api_duration_seconds.labels(service=service_name).observe(duration)
    except httpx.TimeoutException:
        external_api_errors_total.labels(service=service_name).inc()
        msg = f"Timeout during {operation} on {service_name}"
        logger.warning(msg)
        if not suppress_errors:
            raise HTTPRequestError(msg)
    except httpx.ConnectError as e:
        external_api_errors_total.labels(service=service_name).inc()
        msg = f"Connection error during {operation} on {service_name}: {e}"
        logger.warning(msg)
        if not suppress_errors:
            raise HTTPRequestError(msg)
    except httpx.HTTPStatusError as e:
        external_api_errors_total.labels(service=service_name).inc()
        msg = f"HTTP {e.response.status_code} during {operation} on {service_name}"
        logger.warning(msg)
        if not suppress_errors:
            raise HTTPRequestError(msg, status_code=e.response.status_code)
    except Exception as e:
        external_api_errors_total.labels(service=service_name).inc()
        msg = f"Unexpected error during {operation} on {service_name}: {e}"
        logger.error(msg)
        if not suppress_errors:
            raise HTTPRequestError(msg)


async def fetch_json(
    url: str,
    headers: Optional[dict] = None,
    timeout: float = 30.0,
    service_name: str = "External API",
) -> Optional[dict]:
    """
    Fetch JSON from a URL with error handling.

    Args:
        url: The URL to fetch
        headers: Optional request headers
        timeout: Request timeout in seconds
        service_name: Name for logging

    Returns:
        Parsed JSON dict, or None if request failed
    """
    start_time = time.time()
    external_api_requests_total.labels(service=service_name).inc()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            duration = time.time() - start_time
            external_api_duration_seconds.labels(service=service_name).observe(duration)
            return response.json()
    except httpx.TimeoutException:
        external_api_errors_total.labels(service=service_name).inc()
        logger.debug(f"Timeout fetching {url}")
        return None
    except httpx.ConnectError:
        external_api_errors_total.labels(service=service_name).inc()
        logger.debug(f"Connection error fetching {url}")
        return None
    except httpx.HTTPStatusError as e:
        external_api_errors_total.labels(service=service_name).inc()
        if e.response.status_code != 404:  # 404 is often expected
            logger.debug(f"HTTP {e.response.status_code} fetching {url}")
        return None
    except Exception as e:
        external_api_errors_total.labels(service=service_name).inc()
        logger.warning(f"Error fetching {url}: {e}")
        return None


async def post_json(
    url: str,
    data: dict,
    headers: Optional[dict] = None,
    timeout: float = 30.0,
    service_name: str = "External API",
) -> Optional[dict]:
    """
    POST JSON to a URL with error handling.

    Args:
        url: The URL to post to
        data: JSON data to send
        headers: Optional request headers
        timeout: Request timeout in seconds
        service_name: Name for logging

    Returns:
        Parsed JSON response dict, or None if request failed
    """
    start_time = time.time()
    external_api_requests_total.labels(service=service_name).inc()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=data, headers=headers)
            response.raise_for_status()
            duration = time.time() - start_time
            external_api_duration_seconds.labels(service=service_name).observe(duration)
            return response.json()
    except httpx.TimeoutException:
        external_api_errors_total.labels(service=service_name).inc()
        logger.warning(f"Timeout posting to {service_name}")
        return None
    except httpx.ConnectError:
        external_api_errors_total.labels(service=service_name).inc()
        logger.warning(f"Connection error posting to {service_name}")
        return None
    except httpx.HTTPStatusError as e:
        external_api_errors_total.labels(service=service_name).inc()
        logger.warning(f"HTTP {e.response.status_code} posting to {service_name}")
        return None
    except Exception as e:
        external_api_errors_total.labels(service=service_name).inc()
        logger.error(f"Error posting to {service_name}: {e}")
        return None


class InstrumentedAsyncClient:
    """
    A wrapper around httpx.AsyncClient that automatically records metrics.

    Usage:
        async with InstrumentedAsyncClient("EPSS API", timeout=30.0) as client:
            response = await client.get(url)
    """

    def __init__(
        self,
        service_name: str,
        timeout: float = 30.0,
        **kwargs,
    ):
        self.service_name = service_name
        self._client: Optional[httpx.AsyncClient] = None
        self._timeout = timeout
        self._kwargs = kwargs
        self._NOT_STARTED_MSG = "Client not started. Use 'async with' or call start()."

    async def start(self) -> None:
        """Start the underlying client (for long-lived usage)."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout, **self._kwargs)

    async def close(self) -> None:
        """Close the underlying client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "InstrumentedAsyncClient":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    def _record_request(self) -> None:
        """Record that a request was made."""
        external_api_requests_total.labels(service=self.service_name).inc()

    def _record_success(self, duration: float) -> None:
        """Record a successful request."""
        external_api_duration_seconds.labels(service=self.service_name).observe(duration)

    def _record_error(self) -> None:
        """Record a failed request."""
        external_api_errors_total.labels(service=self.service_name).inc()

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make a GET request with metrics."""
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start_time = time.time()
        self._record_request()
        try:
            response = await self._client.get(url, **kwargs)
            self._record_success(time.time() - start_time)
            return response
        except Exception:
            self._record_error()
            raise

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make a POST request with metrics."""
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start_time = time.time()
        self._record_request()
        try:
            response = await self._client.post(url, **kwargs)
            self._record_success(time.time() - start_time)
            return response
        except Exception:
            self._record_error()
            raise

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Make a PUT request with metrics."""
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start_time = time.time()
        self._record_request()
        try:
            response = await self._client.put(url, **kwargs)
            self._record_success(time.time() - start_time)
            return response
        except Exception:
            self._record_error()
            raise

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make a DELETE request with metrics."""
        if self._client is None:
            raise RuntimeError(self._NOT_STARTED_MSG)

        start_time = time.time()
        self._record_request()
        try:
            response = await self._client.delete(url, **kwargs)
            self._record_success(time.time() - start_time)
            return response
        except Exception:
            self._record_error()
            raise

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make an arbitrary HTTP request with metrics."""
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


def with_http_error_handling(
    service_name: str,
    default_return: Any = None,
    log_level: str = "warning",
):
    """
    Decorator for async functions that make HTTP requests.
    Catches common httpx exceptions and returns a default value.

    Usage:
        @with_http_error_handling("GitHub API", default_return=[])
        async def fetch_advisories(cve_ids: list) -> list:
            async with httpx.AsyncClient() as client:
                # ... make requests
                return results

    Args:
        service_name: Name of the service for logging
        default_return: Value to return on error
        log_level: Logging level for errors ("debug", "warning", "error")
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            start_time = time.time()
            external_api_requests_total.labels(service=service_name).inc()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                external_api_duration_seconds.labels(service=service_name).observe(duration)
                return result
            except httpx.TimeoutException:
                external_api_errors_total.labels(service=service_name).inc()
                getattr(logger, log_level)(f"Timeout in {func.__name__} ({service_name})")
                return default_return
            except httpx.ConnectError:
                external_api_errors_total.labels(service=service_name).inc()
                getattr(logger, log_level)(f"Connection error in {func.__name__} ({service_name})")
                return default_return
            except httpx.HTTPStatusError as e:
                external_api_errors_total.labels(service=service_name).inc()
                getattr(logger, log_level)(f"HTTP {e.response.status_code} in {func.__name__} ({service_name})")
                return default_return
            except Exception as e:
                external_api_errors_total.labels(service=service_name).inc()
                logger.error(f"Error in {func.__name__} ({service_name}): {e}")
                return default_return

        return wrapper

    return decorator
