"""What the GitLab and GitHub services share: API calls, paging, OIDC validation, profile emails and team members."""

import asyncio
import logging
import weakref
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Iterable
from contextlib import aclosing, asynccontextmanager
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel

from app.core.cache import cache_service
from app.core.constants import TEAM_ROLE_ADMIN, team_binding_key, team_source
from app.core.http_utils import InstrumentedAsyncClient
from app.core.log_utils import sanitize_for_log
from app.models.github_instance import GitHubInstance
from app.models.gitlab_instance import GitLabInstance
from app.models.team import TeamMember
from app.repositories.teams import MemberSubset, TeamRepository
from app.services.oidc_utils import fetch_jwks
from app.services.oidc_utils import validate_oidc_token as _validate_oidc_token

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


class GitProviderService[InstanceT: GitHubInstance | GitLabInstance, PayloadT: BaseModel](ABC):
    """One configured instance's API, called with its access token; each provider names its host and headers."""

    provider: ClassVar[str]
    _cache_prefix: ClassVar[str]
    _team_provider: ClassVar[str]
    _email_field: ClassVar[str]
    _email_cache_ttl: ClassVar[int]
    _oidc_payload: type[PayloadT]

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

    async def get_current_user_id(self) -> int | None:
        """The id of the account the token belongs to; None when GET /user does not answer it."""
        response = await self._get_ok("/user")
        user_id = None if response is None else json_document(response).get("id")
        return user_id if isinstance(user_id, int) else None

    async def _branch_names(self, endpoint: str) -> list[str] | None:
        """Every branch a paginated branch listing names; None on API failure."""
        branches = await self._api_get_paginated(endpoint)
        return None if branches is None else [branch["name"] for branch in branches]

    async def _send_comment(self, method: str, endpoint: str, body: str) -> bool:
        """Post a review comment, which answers 201, or edit one, which answers 200; any other answer is logged."""
        response = await self._api_request(method, endpoint, json_data={"body": body})
        if response is None:
            return False
        if response.status_code == (201 if method == "POST" else 200):
            return True
        logger.error(
            "%s API %s %s returned HTTP %s: %s", self.provider, method, endpoint, response.status_code, response.text
        )
        return False

    @abstractmethod
    async def _jwks_uris(self) -> list[str]:
        """Where the issuer's signing keys may be fetched, in the order to try them."""

    async def refresh_jwks(self) -> dict | None:
        return await fetch_jwks(self._get_cache_key(f"jwks:{self.base_url}"), self._jwks_uris, self.provider)

    async def get_jwks(self) -> dict | None:
        """The instance's cached key set, fetched on a miss; None while the issuer serves none."""
        cached: dict | None = await cache_service.get(self._get_cache_key(f"jwks:{self.base_url}"))
        return cached or await self.refresh_jwks()

    async def validate_oidc_token(self, token: str) -> PayloadT | None:
        """Validate a CI job's OIDC JWT, refreshing JWKS on key rotation."""
        return await _validate_oidc_token(
            token=token,
            get_jwks=self.get_jwks,
            refresh_jwks=self.refresh_jwks,
            issuer=self.base_url,
            audience=self.instance.oidc_audience,
            payload_model=self._oidc_payload,
            provider_name=self.provider,
        )

    async def _fetch_public_email(self, account: str | int) -> str | None:
        """The profile's public email, "" when it shows none; None when the provider would not answer."""
        response = await self._api_get(f"/users/{account}")
        if response is None:
            return None
        if response.status_code == 404:
            return ""
        if response.status_code != 200:
            logger.warning("%s API GET /users/%s answered HTTP %s", self.provider, account, response.status_code)
            return None
        profile = json_document(response)
        return str(profile.get(self._email_field) or "") if profile else None

    async def _public_emails[K: (str, int)](self, accounts: Iterable[K]) -> dict[K, str] | None:
        """Account -> public email ("" for none) in one cache read; None once one was refused, cancelling those queued."""
        cache_keys = {account: self._get_cache_key(f"user_email:{account}") for account in accounts}
        cached = await cache_service.mget(list(cache_keys.values()))
        emails = {account: value for account, key in cache_keys.items() if isinstance(value := cached.get(key), str)}
        answered: dict[K, str] = {}
        refused = False

        async def fetch_one(account: K) -> None:
            nonlocal refused
            async with request_gate(self._instance_id):
                if refused:
                    return
                email = await self._fetch_public_email(account)
            if email is None:
                refused = True
            else:
                answered[account] = email

        try:
            await asyncio.gather(*(fetch_one(account) for account in cache_keys if account not in emails))
        finally:
            # Also when the caller's deadline cancels the batch, so the next sync resumes from these answers.
            await cache_service.mset(
                {cache_keys[account]: email for account, email in answered.items()}, self._email_cache_ttl
            )
        return None if refused else {**emails, **answered}

    @property
    def _member_source(self) -> str:
        """The provenance of a member this instance resolves, and the subset its sync replaces."""
        return team_source(self._team_provider, self._instance_id)

    def _team_members(self, resolved: Iterable[tuple[str, str]]) -> list[TeamMember]:
        """One member per local user from (user id, role) pairs, an admin role kept over any other."""
        members: dict[str, TeamMember] = {}
        for user_id, role in resolved:
            # Two accounts can resolve to one user: a duplicate breaks add_member's $ne guard, and last-wins demotes.
            if (previous := members.get(user_id)) is None or previous.role != TEAM_ROLE_ADMIN:
                members[user_id] = TeamMember(user_id=user_id, role=role, source=self._member_source)
        return list(members.values())

    async def _write_team_refresh(
        self,
        team_repo: TeamRepository,
        team: dict[str, Any],
        external_id: int,
        renamed: dict[str, Any],
        binding_fields: dict[str, Any],
        team_members: list[TeamMember] | None,
    ) -> None:
        """Write a bound team's rename, binding fields and members, and nothing when nothing changed."""
        # Handed to the server as the subset to replace rather than merged here: the snapshot is several round
        # trips old, and a member added in between would be written back out after the add had reported success.
        subset = (
            MemberSubset(self._member_source, [member.model_dump() for member in team_members])
            if team_members is not None
            else None
        )
        if not renamed and not binding_fields and subset is None:
            return
        await team_repo.update_with_binding(
            team["_id"],
            renamed,
            team_binding_key(self._team_provider, self._instance_id, external_id),
            binding_fields,
            subset,
        )
