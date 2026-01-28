"""
HTTP Utilities

Shared utilities for HTTP client operations, error handling,
and retry logic. Eliminates duplicate httpx exception handling.
"""

import logging
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any, AsyncGenerator, Callable, Optional, TypeVar

import httpx

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
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            yield client
    except httpx.TimeoutException:
        msg = f"Timeout during {operation} on {service_name}"
        logger.warning(msg)
        if not suppress_errors:
            raise HTTPRequestError(msg)
    except httpx.ConnectError as e:
        msg = f"Connection error during {operation} on {service_name}: {e}"
        logger.warning(msg)
        if not suppress_errors:
            raise HTTPRequestError(msg)
    except httpx.HTTPStatusError as e:
        msg = f"HTTP {e.response.status_code} during {operation} on {service_name}"
        logger.warning(msg)
        if not suppress_errors:
            raise HTTPRequestError(msg, status_code=e.response.status_code)
    except Exception as e:
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
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.TimeoutException:
        logger.debug(f"Timeout fetching {url}")
        return None
    except httpx.ConnectError:
        logger.debug(f"Connection error fetching {url}")
        return None
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:  # 404 is often expected
            logger.debug(f"HTTP {e.response.status_code} fetching {url}")
        return None
    except Exception as e:
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
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=data, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.TimeoutException:
        logger.warning(f"Timeout posting to {service_name}")
        return None
    except httpx.ConnectError:
        logger.warning(f"Connection error posting to {service_name}")
        return None
    except httpx.HTTPStatusError as e:
        logger.warning(f"HTTP {e.response.status_code} posting to {service_name}")
        return None
    except Exception as e:
        logger.error(f"Error posting to {service_name}: {e}")
        return None


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
            try:
                return await func(*args, **kwargs)
            except httpx.TimeoutException:
                getattr(logger, log_level)(
                    f"Timeout in {func.__name__} ({service_name})"
                )
                return default_return
            except httpx.ConnectError:
                getattr(logger, log_level)(
                    f"Connection error in {func.__name__} ({service_name})"
                )
                return default_return
            except httpx.HTTPStatusError as e:
                getattr(logger, log_level)(
                    f"HTTP {e.response.status_code} in {func.__name__} ({service_name})"
                )
                return default_return
            except Exception as e:
                logger.error(f"Error in {func.__name__} ({service_name}): {e}")
                return default_return

        return wrapper

    return decorator
