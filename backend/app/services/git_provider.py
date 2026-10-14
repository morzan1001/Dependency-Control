"""What the GitLab and GitHub services share: the token's API calls and Link-header paging."""

import asyncio
import logging
import weakref
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import aclosing, asynccontextmanager
from typing import Any, ClassVar

import httpx

from app.core.cache import cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.log_utils import sanitize_for_log
from app.models.github_instance import GitHubInstance
from app.models.gitlab_instance import GitLabInstance

logger = logging.getLogger(__name__)

_API_TIMEOUT = 10.0

# The largest GitHub organisation here has 204 teams, a request each: in sequence they would outlast the
# resolution budget, and this many at a time stays far below the hundred concurrent requests GitHub tolerates.
_REQUEST_CONCURRENCY = 16

_request_gates: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Semaphore]]" = (
    weakref.WeakKeyDictionary()
)

ResponseHooks = dict[str, list[Callable[[httpx.Response], Awaitable[None]]]]


def request_gate(instance_id: str) -> asyncio.Semaphore:
    """Per instance, as providers limit concurrency per token; process-wide, as one run's ingests put 112 in flight."""
    gates = _request_gates.setdefault(asyncio.get_running_loop(), {})
    return gates.setdefault(instance_id, asyncio.Semaphore(_REQUEST_CONCURRENCY))


def json_document(response: httpx.Response) -> dict[str, Any]:
    """The response body as a document; ``{}`` for anything else, which reads as "the provider did not say"."""
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


async def cached_public_emails[K](
    cache_keys: dict[K, str], fetch: Callable[[K], Awaitable[str | None]], instance_id: str, ttl_seconds: int
) -> dict[K, str] | None:
    """Key -> public email ("" for none) in one cache read; None once a fetch was refused, cancelling those queued."""
    cached = await cache_service.mget(list(cache_keys.values()))
    emails = {key: value for key, cache_key in cache_keys.items() if isinstance(value := cached.get(cache_key), str)}
    answered: dict[K, str] = {}
    refused = False

    async def fetch_one(key: K) -> None:
        nonlocal refused
        async with request_gate(instance_id):
            if refused:
                return
            email = await fetch(key)
        if email is None:
            refused = True
        else:
            answered[key] = email

    try:
        await asyncio.gather(*(fetch_one(key) for key in cache_keys if key not in emails))
    finally:
        # Also when the caller's deadline cancels the batch, so the next sync resumes from these answers.
        await cache_service.mset({cache_keys[key]: email for key, email in answered.items()}, ttl_seconds)
    return None if refused else {**emails, **answered}


class GitProviderService[InstanceT: GitHubInstance | GitLabInstance](ABC):
    """One configured instance's API, called with its access token; each provider names its host and headers."""

    provider: ClassVar[str]
    _cache_prefix: ClassVar[str]

    api_url: str | None

    def __init__(self, instance: InstanceT) -> None:
        self.instance = instance
        self._instance_id = str(instance.id)
        self.base_url = instance.url.rstrip("/")

    def _get_cache_key(self, suffix: str) -> str:
        return f"{self._cache_prefix}:{self._instance_id}:{suffix}"

    @abstractmethod
    def _token_headers(self, token: str) -> dict[str, str]: ...

    def _get_auth_headers(self) -> dict[str, str]:
        if not self.instance.access_token:
            raise ValueError(f"No access token configured for {self.provider} instance '{self.instance.name}'")
        return self._token_headers(self.instance.access_token)

    def _can_call(self) -> bool:
        return bool(self.instance.access_token) and self.api_url is not None

    def _response_hooks(self) -> ResponseHooks:
        return {}

    @asynccontextmanager
    async def _api_client(self) -> AsyncIterator[InstrumentedAsyncClient]:
        async with InstrumentedAsyncClient(
            f"{self.provider} API", timeout=_API_TIMEOUT, event_hooks=self._response_hooks()
        ) as client:
            yield client

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        if not self._can_call():
            return None

        try:
            async with self._api_client() as client:
                return await client.request(
                    method,
                    f"{self.api_url}{endpoint}",
                    headers={**self._get_auth_headers(), **(headers or {})},
                    params=params,
                    json=json_data,
                )
        except Exception as e:
            logger.exception("%s API %s %s failed: %s: %s", self.provider, method, endpoint, type(e).__name__, e)
            return None

    async def _api_get(
        self, endpoint: str, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None
    ) -> httpx.Response | None:
        return await self._api_request("GET", endpoint, params=params, headers=headers)

    def _ok(self, endpoint: str, response: httpx.Response) -> bool:
        """True for 200. A rejected read must not be mistaken for an empty one, so a non-200 is logged here."""
        if response.status_code == 200:
            return True
        logger.warning(
            "%s API GET %s returned HTTP %d", self.provider, sanitize_for_log(endpoint), response.status_code
        )
        return False

    async def _get_ok(self, endpoint: str) -> httpx.Response | None:
        """The 200 answer to a GET; None when there was no answer or a refusal, which is logged."""
        response = await self._api_get(endpoint)
        return response if response is not None and self._ok(endpoint, response) else None

    async def _iter_pages(
        self, endpoint: str, params: dict[str, Any] | None = None, max_pages: int | None = None
    ) -> AsyncGenerator[list[dict[str, Any]] | None]:
        """Each page of a GET paginated by its Link header, then a final None if one failed; a hit ``max_pages`` warns."""
        if not self._can_call():
            yield None
            return
        headers = self._get_auth_headers()
        failed = False
        page = 1
        try:
            async with self._api_client() as session:
                while True:
                    response = await session.get(
                        f"{self.api_url}{endpoint}",
                        headers=headers,
                        params={**(params or {}), "page": page, "per_page": 100},
                    )
                    if not self._ok(endpoint, response):
                        failed = True
                        break

                    items = response.json()
                    if not items:
                        break
                    yield items

                    if 'rel="next"' not in response.headers.get("link", ""):
                        break
                    if page == max_pages:
                        logger.warning(
                            "%s API GET %s hit the pagination cap of %d page(s) but the Link header still offers "
                            'rel="next". Result is TRUNCATED.',
                            self.provider,
                            sanitize_for_log(endpoint),
                            max_pages,
                        )
                        break
                    page += 1
        except Exception as e:
            logger.warning(
                "%s API paginated GET %s failed: %s: %s",
                self.provider,
                sanitize_for_log(endpoint),
                type(e).__name__,
                e,
            )
            failed = True
        if failed:
            yield None

    async def _api_get_paginated(
        self, endpoint: str, params: dict[str, Any] | None = None, max_pages: int | None = None
    ) -> list[dict[str, Any]] | None:
        """Every item of a paginated GET, or None when a page failed or no call may go out."""
        items: list[dict[str, Any]] = []
        async with aclosing(self._iter_pages(endpoint, params, max_pages)) as pages:
            async for page in pages:
                if page is None:
                    return None
                items.extend(page)
        return items
