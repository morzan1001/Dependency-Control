import asyncio
import logging
import urllib.parse
import weakref
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import aclosing, asynccontextmanager
from datetime import datetime, timezone
from typing import Any, NamedTuple

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.cache import cache_service
from app.core.constants import (
    GITHUB_API_URL,
    GITHUB_JWKS_CACHE_TTL,
    GITHUB_JWKS_URI_CACHE_TTL,
    GITHUB_ORG_REPO_MAP_CACHE_TTL,
    GITHUB_TEAM_SYNC_CACHE_TTL,
    GITHUB_USER_EMAIL_CACHE_TTL,
    MAX_PROJECT_TEAMS,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
    TEAM_SOURCE_GITHUB,
    team_binding_key,
    team_source,
)
from app.core.http_utils import InstrumentedAsyncClient
from app.core.log_utils import sanitize_for_log
from app.models.github_api import GitHubIssueComment, GitHubOIDCPayload, GitHubPullRequest
from app.models.github_instance import GITHUB_SHARED_OIDC_ISSUER, GitHubInstance
from app.models.team import GitHubTeamBinding, Team, TeamMember, TeamSyncResult, binding_of
from app.repositories.teams import MemberSubset, TeamRepository
from app.repositories.users import UserRepository
from app.services.oidc_utils import validate_oidc_token as _validate_oidc_token

logger = logging.getLogger(__name__)

_GITHUB_COM_JWKS_URI = "https://token.actions.githubusercontent.com/.well-known/jwks"

_PUBLIC_GITHUB_WEB_HOSTS = frozenset({"github.com", "www.github.com"})


_GITHUB_API_TIMEOUT = 10.0

# The resolution runs inside the ingest request. One deadline covers every call it makes -- the
# per-team checks and the per-member reads that follow them -- so a GitHub that answers slowly costs
# an ingest this much once, rather than this much per phase.
_GITHUB_RESOLUTION_TIMEOUT = 30.0

_DEFAULT_ACCEPT = "application/vnd.github+json"
# Without this media type the team/repository check answers 204 with no body, and the body is the
# only place the team's permission level on the repository is reported.
_REPOSITORY_ACCEPT = "application/vnd.github.v3.repository+json"

# One request per team of the organisation, and the largest one here has 204 of them. Run in
# sequence they would outlast the resolution budget; this many at a time finishes the walk well
# inside it and stays far below the hundred concurrent requests GitHub tolerates.
_GITHUB_ORG_WALK_CONCURRENCY = 16

# The walk's own share of the resolution budget, counted from its first listing's turn at the gate.
# Exceeding it is recorded rather than abandoned, so the next ingest reads the failure from the
# cache instead of paying the whole walk again.
_GITHUB_ORG_WALK_TIMEOUT = 15.0

# The locking helper stores a failed fetch as a bare {} for an hour, which would read as an empty
# answer; an answer wrapped in this field carries its own None for the TTL it is cached under.
_CACHED_FIELD = "value"

# Write access or better. Read access is not ownership: a group holding every repository of the
# organisation on pull would otherwise own the whole estate.
_WRITE_PERMISSIONS = ("push", "maintain", "admin")

_GITHUB_TEAM_ROLES = (("maintainer", TEAM_ROLE_ADMIN), ("member", TEAM_ROLE_MEMBER))

_org_walk_gates: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Semaphore]]" = (
    weakref.WeakKeyDictionary()
)


def split_repo_path(path: str | None) -> tuple[str, str] | None:
    """``owner/repo`` as its two parts, or None unless both are present."""
    owner, _, repo = (path or "").partition("/")
    return (owner, repo) if owner and repo else None


def _org_walk_gate(instance_id: str) -> asyncio.Semaphore:
    """The limit on one instance's sync requests in flight, shared by every sync in this process.

    Per instance because GitHub limits concurrency per token. Shared because one workflow run fans
    out into many ingests: eight of them measured 112 requests in flight against a limit of 16.
    """
    gates = _org_walk_gates.setdefault(asyncio.get_running_loop(), {})
    return gates.setdefault(instance_id, asyncio.Semaphore(_GITHUB_ORG_WALK_CONCURRENCY))


def response_ok(provider: str, endpoint: str, response: httpx.Response) -> bool:
    """True for 200. A rejected read must not be mistaken for an empty one, so a non-200 is logged here."""
    if response.status_code == 200:
        return True
    logger.warning("%s API GET %s returned HTTP %d", provider, sanitize_for_log(endpoint), response.status_code)
    return False


def _json_document(response: httpx.Response) -> dict[str, Any]:
    """The response body as a document; ``{}`` for anything else, which reads as "GitHub did not say"."""
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _team_writes_to(repository: dict[str, Any]) -> bool | None:
    """Whether the team's access to the repository is write or better; None when the listing did not
    say, which must not read as read-only and retire the owners of a whole organisation."""
    permissions = repository.get("permissions")
    if not isinstance(permissions, dict):
        return None
    return any(bool(permissions.get(level)) for level in _WRITE_PERMISSIONS)


def _auto_team_name(org: str, slug: str) -> str:
    """The name a team gets while nobody has renamed it."""
    return f"GitHub Team: {org}/{slug}"


def _auto_team_description(org: str, slug: str) -> str:
    return f"Imported from GitHub team {org}/{slug}"


def _team_id(team: dict[str, Any]) -> int | None:
    """None for an id we cannot order by; such a team is skipped, never fatal to the whole repository."""
    try:
        return int(team["id"])
    except (KeyError, TypeError, ValueError):
        return None


def _team_slug(team: dict[str, Any]) -> str | None:
    """None for a team the members endpoint cannot be addressed by; skipped like a malformed id."""
    slug = team.get("slug")
    return str(slug) if slug else None


def build_team_slug_map(org_teams: list[dict[str, Any]]) -> dict[int, str]:
    """Team id -> current slug from GET /orgs/{org}/teams.

    A stored slug would address the wrong team after a rename, so the slug the API is called with
    is always the one the organisation listing reports for the bound team number.
    """
    return {
        team_id: slug
        for team in org_teams
        if (team_id := _team_id(team)) is not None and (slug := _team_slug(team)) is not None
    }


def build_org_team_options(org_teams: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The teams of an organisation a human can bind to, with the parent that tells two same-named
    nested teams apart. An entry that cannot address a team is left out, as it is everywhere else."""
    options = []
    for team in org_teams:
        team_id = _team_id(team)
        slug = _team_slug(team)
        if team_id is None or slug is None:
            continue
        parent = team.get("parent") or {}
        options.append(
            {
                "id": team_id,
                "slug": slug,
                "name": str(team.get("name") or slug),
                "parent_name": str(parent["name"]) if parent.get("name") else None,
            }
        )
    return options


class _HolderBinding(NamedTuple):
    """A GitHub team holding the repository, before its Dependency Control team is settled.

    ``team`` carries the bound team where one is bound, and None for a group whose team is still to
    be adopted or created — which happens only once the whole set is known to fit the project.
    """

    team_id: int
    slug: str
    team: dict[str, Any] | None


class GitHubCoreRateLimit(NamedTuple):
    """The core budget of a token; ``remaining == 0`` is what turns every other call into a 403."""

    remaining: int
    reset_at: datetime


def _hostname(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def is_public_github(github_url: str | None, issuer_url: str) -> bool:
    """Whether an instance's API, and so its access token, belongs to github.com rather than a GHES host."""
    # The parsed host, not a substring: "github.company.com" and "github.com.corp.internal" are GHES.
    if github_url:
        return _hostname(github_url) in _PUBLIC_GITHUB_WEB_HOSTS
    return _hostname(issuer_url) == _hostname(GITHUB_SHARED_OIDC_ISSUER)


def github_api_headers(token: str | None) -> dict[str, str]:
    """REST headers for api.github.com, pinned to one API version; anonymous without a token."""
    headers = {"Accept": _DEFAULT_ACCEPT, "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class GitHubService:
    """OIDC token validation and API operations for github.com and GHES instances."""

    def __init__(self, github_instance: GitHubInstance):
        self.instance = github_instance
        self._instance_id = str(github_instance.id)
        self.base_url = github_instance.url.rstrip("/")
        self._cache_key_prefix = f"gh_instance:{github_instance.id}"

        github_url = (github_instance.github_url or "").rstrip("/")
        self.api_url: str | None
        if is_public_github(github_url, github_instance.url):
            self.api_url = GITHUB_API_URL
        elif github_url:
            self.api_url = f"{github_url}/api/v3"
        else:
            # A GHES issuer without a web URL names no API host; its token is sent nowhere.
            self.api_url = None

    def _get_cache_key(self, suffix: str) -> str:
        """Generate cache key for this specific instance."""
        return f"github:{self._cache_key_prefix}:{suffix}"

    def _get_auth_headers(self, accept: str = _DEFAULT_ACCEPT) -> dict[str, str]:
        if not self.instance.access_token:
            raise ValueError(f"No access token configured for GitHub instance '{self.instance.name}'")
        return {"Authorization": f"Bearer {self.instance.access_token}", "Accept": accept}

    @asynccontextmanager
    async def _api_client(self) -> AsyncIterator[InstrumentedAsyncClient]:
        async with InstrumentedAsyncClient("GitHub API", timeout=_GITHUB_API_TIMEOUT) as client:
            yield client

    async def _api_get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        accept: str = _DEFAULT_ACCEPT,
    ) -> httpx.Response | None:
        if not self.instance.access_token or self.api_url is None:
            return None

        try:
            async with self._api_client() as client:
                return await client.get(
                    f"{self.api_url}{endpoint}",
                    headers=self._get_auth_headers(accept),
                    params=params,
                )
        except Exception as e:
            logger.exception("GitHub API GET %s failed: %s", endpoint, e)
            return None

    async def _api_post(self, endpoint: str, json_data: dict[str, Any] | None = None) -> httpx.Response | None:
        if not self.instance.access_token or self.api_url is None:
            return None

        try:
            async with self._api_client() as client:
                return await client.post(
                    f"{self.api_url}{endpoint}",
                    headers=self._get_auth_headers(),
                    json=json_data,
                )
        except Exception as e:
            logger.exception("GitHub API POST %s failed: %s", endpoint, e)
            return None

    async def _api_patch(self, endpoint: str, json_data: dict[str, Any] | None = None) -> httpx.Response | None:
        if not self.instance.access_token or self.api_url is None:
            return None

        try:
            async with self._api_client() as client:
                return await client.patch(
                    f"{self.api_url}{endpoint}",
                    headers=self._get_auth_headers(),
                    json=json_data,
                )
        except Exception as e:
            logger.exception("GitHub API PATCH %s failed: %s", endpoint, e)
            return None

    async def _iter_pages(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        max_pages: int | None = 10,
    ) -> AsyncGenerator[list[dict[str, Any]] | None]:
        """Each page of a GET paginated by GitHub's Link header, then a final None when one failed.

        ``max_pages=None`` reads every page; a finite cap that is hit logs a truncation WARNING.
        """
        if not self.instance.access_token or self.api_url is None:
            yield None
            return

        failed = False
        page = 1
        item_count = 0
        try:
            async with self._api_client() as client:
                while max_pages is None or page <= max_pages:
                    response = await client.get(
                        f"{self.api_url}{endpoint}",
                        headers=self._get_auth_headers(),
                        params={**(params or {}), "page": page, "per_page": 100},
                    )
                    if response.status_code != 200:
                        logger.error(
                            f"GitHub API GET {sanitize_for_log(endpoint)} page {page} failed: {response.status_code}"
                        )
                        failed = True
                        break

                    items = response.json()
                    if not items:
                        break
                    item_count += len(items)
                    yield items

                    if 'rel="next"' not in response.headers.get("link", ""):
                        break
                    if self._cap_reached(endpoint, page, max_pages, item_count):
                        break
                    page += 1
        except Exception as e:
            logger.exception("GitHub API paginated GET %s failed: %s", sanitize_for_log(endpoint), e)
            failed = True
        if failed:
            yield None

    async def _api_get_paginated(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        max_pages: int | None = 10,
    ) -> list[dict[str, Any]] | None:
        """Every item of a paginated GET, or None when a page failed."""
        all_items: list[dict[str, Any]] = []
        async for items in self._iter_pages(endpoint, params, max_pages):
            if items is None:
                return None
            all_items.extend(items)
        return all_items

    @staticmethod
    def _cap_reached(endpoint: str, page: int, max_pages: int | None, item_count: int) -> bool:
        """True (and logs a WARNING) when a finite cap is hit while the Link header still offers a next page."""
        if max_pages is None or page < max_pages:
            return False
        logger.warning(
            "GitHub API GET %s hit the pagination cap of %d page(s) (%d items) but the Link header "
            'still offers rel="next". Result is TRUNCATED.',
            sanitize_for_log(endpoint),
            max_pages,
            item_count,
        )
        return True

    async def list_branches(self, owner: str, repo: str) -> list[str] | None:
        """Fetches all branch names from a GitHub repository. Returns None on API failure."""
        branches = await self._api_get_paginated(f"/repos/{owner}/{repo}/branches")
        if branches is None:
            return None
        return [b["name"] for b in branches]

    async def get_default_branch(self, owner: str, repo: str) -> str | None:
        """The repository's default branch. Returns None on API failure."""
        endpoint = f"/repos/{owner}/{repo}"
        response = await self._api_get(endpoint)
        if response is None or not response_ok("GitHub", endpoint, response):
            return None
        branch = response.json().get("default_branch")
        return str(branch) if branch else None

    async def _cached(
        self,
        suffix: str,
        fetch: Callable[[], Awaitable[Any]],
        expected_type: type,
        *,
        ttl_seconds: int = GITHUB_TEAM_SYNC_CACHE_TTL,
        max_wait_seconds: float = 5.0,
    ) -> Any:
        """One fetch per key and TTL across every pod, its None cached for the TTL as well."""

        async def wrapped() -> dict[str, Any]:
            return {_CACHED_FIELD: await fetch()}

        cached = await cache_service.get_or_fetch_with_lock(
            self._get_cache_key(suffix), wrapped, ttl_seconds=ttl_seconds, max_wait_seconds=max_wait_seconds
        )
        value = cached.get(_CACHED_FIELD) if isinstance(cached, dict) else None
        return value if isinstance(value, expected_type) else None

    async def team_writes_to_repository(self, org: str, team_slug: str, team_id: int, repo: str) -> bool | None:
        """Whether one team holds one repository with write access or better; None when GitHub did
        not answer.

        Answers on a read-only organisation token, which asking the repository for its teams
        cannot: that requires the admin role on every single repository.
        """
        cache_key = self._get_cache_key(f"team_write:{org}/{team_id}:{org}/{repo}")
        cached: bool | None = await cache_service.get(cache_key)
        if cached is not None:
            return cached

        endpoint = f"/orgs/{org}/teams/{team_slug}/repos/{org}/{repo}"
        async with _org_walk_gate(self._instance_id):
            response = await self._api_get(endpoint, accept=_REPOSITORY_ACCEPT)
        if response is None:
            return None

        if response.status_code == 200:
            # This endpoint is a permission check, not a write check: it answers 200 on pull as
            # readily as on admin, so the level in the body is what decides, exactly as it does
            # when the organisation walk reads the same repository from the team's listing.
            writes = _team_writes_to(_json_document(response))
            if writes is None:
                logger.warning(
                    "GitHub answered for team %s/%s on %s/%s without saying what the team's access "
                    "is; the holder stays undetermined.",
                    org,
                    team_slug,
                    org,
                    repo,
                )
                return None
        elif response.status_code == 404:
            writes = False
        else:
            # A refusal read as "this team does not hold the repository" would retire the team
            # from every project it owns.
            logger.warning("GitHub API GET %s returned HTTP %d", endpoint, response.status_code)
            return None

        await cache_service.set(cache_key, writes, ttl_seconds=GITHUB_TEAM_SYNC_CACHE_TTL)
        return writes

    async def _repository_visible(self, org: str, repo: str) -> bool | None:
        """Whether the token can see the repository at all; None when GitHub did not answer."""

        async def fetch() -> bool | None:
            endpoint = f"/repos/{org}/{repo}"
            async with _org_walk_gate(self._instance_id):
                response = await self._api_get(endpoint)
            if response is None:
                return None
            if response.status_code != 200:
                logger.warning(
                    "GitHub API GET %s returned HTTP %d; the token cannot see the repository.",
                    endpoint,
                    response.status_code,
                )
                return False
            return True

        visible: bool | None = await self._cached(f"repository_visible:{org}/{repo}", fetch, bool)
        return visible

    async def get_org_teams(self, org: str) -> list[dict[str, Any]] | None:
        """Every team of an organisation, with the parent that tells two same-named ones apart."""

        async def fetch() -> list[dict[str, Any]] | None:
            async with _org_walk_gate(self._instance_id):
                teams = await self._api_get_paginated(f"/orgs/{org}/teams", max_pages=None)
            if teams is None:
                return None
            return [
                {
                    "id": team.get("id"),
                    "slug": team.get("slug"),
                    "name": team.get("name"),
                    "parent": {"name": parent["name"]}
                    if (parent := team.get("parent")) and parent.get("name")
                    else None,
                }
                for team in teams
            ]

        teams: list[dict[str, Any]] | None = await self._cached(f"org_team_list:{org}", fetch, list)
        return teams

    async def _list_team_repositories(self, org: str, slug: str, budget: asyncio.Timeout) -> list[str] | None:
        """The full names one team may write to, lower-cased; None when a page went unanswered or
        did not say what the team's access is.

        A team with mere read access is not an owner: the people who can change the code are.
        """
        written: list[str] = []
        async with _org_walk_gate(self._instance_id):
            if budget.when() is None:
                budget.reschedule(asyncio.get_running_loop().time() + _GITHUB_ORG_WALK_TIMEOUT)
            async with aclosing(self._iter_pages(f"/orgs/{org}/teams/{slug}/repos", max_pages=None)) as pages:
                async for repositories in pages:
                    if repositories is None:
                        return None
                    for repository in repositories:
                        writes = _team_writes_to(repository)
                        if writes is None:
                            logger.warning(
                                "GitHub listed a repository of team %s/%s without the team's permissions; "
                                "the organisation's holders stay undetermined.",
                                org,
                                slug,
                            )
                            return None
                        if writes and (full_name := repository.get("full_name")):
                            written.append(str(full_name).lower())
        return written

    async def _walk_org_repository_map(self, org: str, slug_map: dict[int, str]) -> dict[str, list[int]] | None:
        """Walk every team of the organisation. None when one of them went unanswered or the walk
        outlasted its budget.

        Half a walk names the wrong holders rather than fewer of them: the teams it did not reach
        would read as teams that hold nothing, so a partial result is no result.
        """
        try:
            async with asyncio.timeout(None) as budget:
                listings = await asyncio.gather(
                    *(self._list_team_repositories(org, slug, budget) for slug in slug_map.values())
                )
        except TimeoutError:
            logger.warning(
                "Walking the %d team(s) of GitHub organisation %s took longer than %.0fs; the "
                "organisation stays undetermined until the entry expires, rather than being walked "
                "again by every ingest.",
                len(slug_map),
                org,
                _GITHUB_ORG_WALK_TIMEOUT,
            )
            return None

        repo_map: dict[str, list[int]] = {}
        for team_id, repositories in zip(slug_map, listings, strict=True):
            if repositories is None:
                return None
            for full_name in repositories:
                repo_map.setdefault(full_name, []).append(team_id)
        return repo_map

    async def get_org_repository_map(self, org: str, slug_map: dict[int, str]) -> dict[str, list[int]] | None:
        """Repository full name -> the teams of ``org`` holding it; None when the walk did not finish.

        Asking the repository which teams hold it needs the admin role on that repository, so the
        only answer a read-only organisation token can give costs a request per team. One walk per
        organisation and TTL, behind the stampede lock: the jobs of one workflow run arrive
        together, and eight of them walking a 204-team organisation is 1632 of 5000 hourly requests.
        """
        repo_map: dict[str, list[int]] | None = await self._cached(
            f"org_repository_map:{org}",
            lambda: self._walk_org_repository_map(org, slug_map),
            dict,
            ttl_seconds=GITHUB_ORG_REPO_MAP_CACHE_TTL,
            # The walk's budget starts at the gate, so only deadlines bound it; a waiter's own ends its wait first.
            max_wait_seconds=_GITHUB_RESOLUTION_TIMEOUT,
        )
        return repo_map

    async def count_org_teams(self, org: str) -> int | None:
        """How many teams the token can read in an organisation; None when the API refuses.

        Uncached, unlike ``get_org_teams``: a connection test must observe the token as it is now,
        not as it was five minutes ago.
        """
        teams = await self._api_get_paginated(f"/orgs/{org}/teams", max_pages=None)
        return None if teams is None else len(teams)

    async def get_team_members(self, org: str, team_slug: str, team_id: int) -> list[dict[str, Any]] | None:
        """Logins tagged with their role. Cached on the numeric id: the slug is renameable."""

        async def fetch() -> list[dict[str, Any]] | None:
            endpoint = f"/orgs/{org}/teams/{team_slug}/members"
            members: list[dict[str, Any]] = []
            # The endpoint returns plain user objects, so the role can only come from the query.
            for github_role, role in _GITHUB_TEAM_ROLES:
                async with _org_walk_gate(self._instance_id):
                    page = await self._api_get_paginated(endpoint, params={"role": github_role}, max_pages=None)
                if page is None:
                    return None
                members.extend({"login": user["login"], "role": role} for user in page if user.get("login"))
            return members

        members: list[dict[str, Any]] | None = await self._cached(f"team_member_roles:{org}/{team_id}", fetch, list)
        return members

    async def get_viewer_organisations(self) -> list[dict[str, Any]] | None:
        """Organisations the token's own identity belongs to. Uncached: a connection test must
        observe the token as it is now, not as it was five minutes ago."""
        return await self._api_get_paginated("/user/orgs", max_pages=None)

    async def get_core_rate_limit(self) -> GitHubCoreRateLimit | None:
        """The token's core budget, or None when it cannot be read (GHES answers 404 with rate limiting off).

        GitHub does not charge this endpoint against the budget, so it keeps answering 200 while every
        other call 403s -- which is the only way to tell an exhausted token from an unauthorised one.
        """
        response = await self._api_get("/rate_limit")
        if response is None or response.status_code != 200:
            return None
        try:
            core = response.json()["resources"]["core"]
            return GitHubCoreRateLimit(
                remaining=int(core["remaining"]),
                reset_at=datetime.fromtimestamp(int(core["reset"]), tz=timezone.utc),
            )
        except (KeyError, TypeError, ValueError, OverflowError, OSError) as e:
            logger.warning("GitHub rate limit response could not be read: %s", e)
            return None

    async def _fetch_public_email(self, login: str) -> str | None:
        """The profile's public email, "" when it shows none; None when GitHub would not answer."""
        response = await self._api_get(f"/users/{login}")
        if response is None:
            return None
        if response.status_code == 404:
            return ""
        if response.status_code != 200:
            logger.warning("GitHub API GET /users/%s failed: %s", login, response.status_code)
            return None
        return str(_json_document(response).get("email") or "")

    async def _public_emails(self, logins: list[str]) -> dict[str, str] | None:
        """Login -> public email ("" for none); None once GitHub refused one, which cancels the reads still queued."""
        keys = {login: self._get_cache_key(f"user_email:{login}") for login in logins}
        cached = await cache_service.mget(list(keys.values()))
        emails = {login: value for login, key in keys.items() if isinstance(value := cached.get(key), str)}
        refused = False

        async def fetch(login: str) -> str | None:
            nonlocal refused
            async with _org_walk_gate(self._instance_id):
                if refused:
                    return None
                email = await self._fetch_public_email(login)
            refused = refused or email is None
            return email

        missing = [login for login in logins if login not in emails]
        fetched = dict(zip(missing, await asyncio.gather(*(fetch(login) for login in missing)), strict=True))
        answered = {login: email for login, email in fetched.items() if email is not None}
        await cache_service.mset({keys[login]: email for login, email in answered.items()}, GITHUB_USER_EMAIL_CACHE_TTL)
        return None if refused else {**emails, **answered}

    async def _resolve_logins(self, logins: list[str], user_repo: UserRepository) -> dict[str, dict[str, Any]] | None:
        """Login -> the EXISTING local user that verified its public email; None when GitHub would
        not say. A matching username proves nothing."""
        emails = await self._public_emails(logins)
        if emails is None:
            return None
        wanted = sorted({email for email in emails.values() if email})
        users = await user_repo.find_raw_by_verified_emails(wanted) if wanted else []
        by_email = {str(user.get("email", "")).lower(): user for user in users}
        return {login: user for login, email in emails.items() if email and (user := by_email.get(email.lower()))}

    async def resolve_login(self, login: str, user_repo: UserRepository) -> dict[str, Any] | None:
        """The EXISTING local user that verified the login's public email, if GitHub names one."""
        return (await self._resolve_logins([login], user_repo) or {}).get(login)

    @property
    def _member_source(self) -> str:
        """The provenance of a member this instance resolves, and the subset its sync replaces."""
        return team_source(TEAM_SOURCE_GITHUB, self._instance_id)

    async def _build_team_members(
        self,
        members: list[dict[str, Any]],
        user_repo: UserRepository,
    ) -> list[TeamMember] | None:
        """Map GitHub members onto existing local users, tagged with this instance; None when GitHub
        would not answer for one of them."""
        users = await self._resolve_logins([member["login"] for member in members], user_repo)
        if users is None:
            return None
        resolved: dict[str, TeamMember] = {}
        for member in members:
            login = member["login"]
            user = users.get(login)
            if user is None:
                # Sync never creates users; a real member is added on their next sync after
                # logging in via OIDC.
                logger.debug("Skipping GitHub member that resolved to no local user (login=%s).", login)
                continue
            role = member["role"]
            user_id = str(user["_id"])
            # Two logins can resolve to one local user. A duplicate entry breaks add_member's $ne
            # guard, and the next sync's last-wins merge would silently demote the admin entry.
            previous = resolved.get(user_id)
            if previous is not None and previous.role == TEAM_ROLE_ADMIN:
                continue
            resolved[user_id] = TeamMember(user_id=user_id, role=role, source=self._member_source)
        return list(resolved.values())

    @staticmethod
    def _renamed_fields(team: dict[str, Any], binding: dict[str, Any], org: str, team_slug: str) -> dict[str, Any]:
        """The name to follow GitHub with, while the team still carries the one this binding generated.

        A team its owner renamed keeps that name for good, and so does one named after another
        instance's binding: following it would rename the team back and forth between the two.
        """
        stored_org, stored_slug = binding.get("org"), binding.get("slug")
        # Organisations are stored in whatever case they were first written in.
        if (
            not stored_org
            or not stored_slug
            or (stored_org.casefold(), stored_slug) == (org.casefold(), team_slug)
            or str(team.get("name") or "").casefold() != _auto_team_name(stored_org, stored_slug).casefold()
        ):
            return {}
        return {"name": _auto_team_name(org, team_slug), "description": _auto_team_description(org, team_slug)}

    async def _refresh_team(
        self,
        team_repo: TeamRepository,
        org: str,
        holder: _HolderBinding,
        team: dict[str, Any],
        team_members: list[TeamMember] | None,
    ) -> None:
        """Write what GitHub has since changed about a holding team.

        ``team_members`` is None to leave the stored members alone, which the rename must not hang
        on: barely a login resolves here, so a name would otherwise never follow a renamed team.
        """
        binding = binding_of(team, self._instance_id) or {}
        updates: dict[str, Any] = self._renamed_fields(team, binding, org, holder.slug)
        # Handed to the server as the subset to replace rather than merged here: the snapshot is
        # several round trips old, and a member added in between would be written back out of the
        # team after the add had already reported success.
        subset = (
            MemberSubset(self._member_source, [member.model_dump() for member in team_members])
            if team_members is not None
            else None
        )
        # The binding is the numeric team id, so a renamed slug has to follow it.
        binding_fields = {"slug": holder.slug} if binding.get("slug") != holder.slug else {}
        if not updates and not binding_fields and subset is None:
            return
        await team_repo.update_with_binding(
            team["_id"],
            updates,
            team_binding_key(TEAM_SOURCE_GITHUB, self._instance_id, holder.team_id),
            binding_fields,
            subset,
        )

    async def _team_for_github_group(
        self,
        team_repo: TeamRepository,
        org: str,
        team_id: int,
        slug: str,
    ) -> dict[str, Any] | None:
        """The Dependency Control team for a GitHub team: the one bound to it, or a new one.

        A binding hands every member of that team project-admin over everything the group holds,
        which is system:manage's to grant, while a team's name is its own admin's to set; binding
        by name let anyone who can name a team collect the group's repositories.

        Created even when GitHub names members none of whom resolve: logins here are personal
        handles while usernames are directory ids, so requiring a resolved member — as the GitLab
        sync does — would mean never creating anything. An empty team its owner fills by hand is
        worth more than a group that never appears.
        """
        existing = await team_repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, self._instance_id, team_id)
        if existing:
            return existing

        team = Team(
            name=_auto_team_name(org, slug),
            description=_auto_team_description(org, slug),
            bindings=[GitHubTeamBinding(instance_id=self._instance_id, org=org, external_id=team_id, slug=slug)],
        )
        created = await team_repo.create_bound(team)
        if created is not None and created["_id"] == team.id:
            logger.info("Created team '%s' for GitHub team %s/%s (id=%d).", team.name, org, slug, team_id)
        return created

    def _address_bound_teams(
        self,
        org: str,
        repo: str,
        bound_teams: list[dict[str, Any]],
        slug_map: dict[int, str],
        holder_ids: list[int],
        current_owner_ids: set[str],
    ) -> list[_HolderBinding] | None:
        """The bound teams to ask directly: those the map names as holders and the current owners.
        None when a current owner cannot be asked.

        The organisation listing omits the teams the token cannot see, secret ones above all.
        Skipping such an owner would hand the repository to whichever team did answer and report
        that as a determined result; a binding that owns nothing here has nothing to lose.
        """
        addressed = []
        for team in bound_teams:
            owns = str(team["_id"]) in current_owner_ids
            team_id = (binding_of(team, self._instance_id) or {}).get("external_id")
            if not isinstance(team_id, int) or (slug := slug_map.get(team_id)) is None:
                logger.warning(
                    "Team %s is bound to GitHub team %s of %s, which the organisation listing does not show; %s.",
                    team.get("_id"),
                    team_id,
                    org,
                    f"the owner of {org}/{repo} stays undetermined until the binding is corrected"
                    if owns
                    else f"leaving it out of {org}/{repo}",
                )
                if owns:
                    return None
                continue
            if owns or team_id in holder_ids:
                addressed.append(_HolderBinding(team_id, slug, team))
        return addressed

    async def _collect_repository_candidates(
        self, org: str, repo: str, addressed: list[_HolderBinding]
    ) -> list[_HolderBinding] | None:
        """The addressed teams that hold the repository. None when a single check went unanswered:
        an incomplete set would retire the owners whose answers are the ones missing.
        """
        accesses = await asyncio.gather(
            *(self.team_writes_to_repository(org, holder.slug, holder.team_id, repo) for holder in addressed)
        )
        if None in accesses:
            return None
        return [holder for holder, writes in zip(addressed, accesses, strict=True) if writes]

    def _discover_bindings(
        self,
        org: str,
        repo: str,
        holder_ids: list[int],
        addressed: list[_HolderBinding],
        slug_map: dict[int, str],
    ) -> list[_HolderBinding]:
        """The organisation's own groups holding the repository, addressed but not yet created.

        Read on every sync rather than only when nothing bound holds the repository: a group
        granted access after the first owner was found would otherwise never be seen.
        """
        # Already asked about this repository directly, and that answer is the fresher one.
        asked = {holder.team_id for holder in addressed}
        bindings: list[_HolderBinding] = []
        for team_id in holder_ids:
            if team_id in asked:
                continue
            slug = slug_map.get(team_id)
            if slug is None:
                # The map outlives the team listing, so a team dissolved since the walk lands here.
                logger.warning(
                    "GitHub team %d holds %s/%s in the cached map of %s but the organisation no longer "
                    "lists it; leaving it out.",
                    team_id,
                    org,
                    repo,
                    org,
                )
                continue
            bindings.append(_HolderBinding(team_id, slug, None))
        return bindings

    async def _resolve_repository_holders(
        self,
        org: str,
        repo: str,
        bound_teams: list[dict[str, Any]],
        current_owner_ids: set[str],
    ) -> list[_HolderBinding] | None:
        """Every GitHub team holding the repository, or None when GitHub could not answer for all
        of them. Reads only: nothing is written before the whole set is known."""
        org_teams = await self.get_org_teams(org)
        if org_teams is None:
            logger.warning(
                "Could not list the teams of GitHub organisation %s; leaving %s/%s untouched.", org, org, repo
            )
            return None

        slug_map = build_team_slug_map(org_teams)
        repo_map = await self.get_org_repository_map(org, slug_map)
        if repo_map is None:
            logger.warning(
                "Could not map the teams of GitHub organisation %s onto its repositories; leaving %s/%s untouched.",
                org,
                org,
                repo,
            )
            return None

        holder_ids = repo_map.get(f"{org}/{repo}".lower(), [])
        addressed = self._address_bound_teams(org, repo, bound_teams, slug_map, holder_ids, current_owner_ids)
        if addressed is None:
            return None
        bound = await self._collect_repository_candidates(org, repo, addressed)
        if bound is None:
            return None
        holders = [*bound, *self._discover_bindings(org, repo, holder_ids, addressed, slug_map)]
        # GitHub answers 404 for a repository the token cannot see exactly as for a team without access to it.
        if holders or await self._repository_visible(org, repo):
            return holders
        return None

    async def _resolve_holder_members(
        self,
        user_repo: UserRepository,
        org: str,
        repo: str,
        holder: _HolderBinding,
    ) -> list[TeamMember] | None:
        """The members to store for a holding team, or None to leave the stored ones alone."""
        # An empty list is a team nobody is left in, and its members must go; only None is a failure.
        members = await self.get_team_members(org, holder.slug, holder.team_id)
        if members is None:
            logger.warning(
                "Failed to fetch members for GitHub team %s/%s (id=%d) while syncing %s/%s. Skipping member sync.",
                org,
                holder.slug,
                holder.team_id,
                org,
                repo,
            )
            return None

        team_members = await self._build_team_members(members, user_repo)
        if team_members is None:
            # Whoever GitHub would not answer for is absent from the resolved set, and writing it
            # would retire them from the team along with the role it gives them on its projects.
            logger.warning(
                "GitHub would not say who the %d members of team %s/%s (id=%d) are while syncing %s/%s; "
                "leaving the existing members untouched.",
                len(members),
                org,
                holder.slug,
                holder.team_id,
                org,
                repo,
            )
        return team_members

    async def sync_team_from_github(
        self,
        db: AsyncIOMotorDatabase,
        repository_path: str,
        *,
        current_owner_ids: set[str],
        owner_budget: int = MAX_PROJECT_TEAMS,
    ) -> TeamSyncResult:
        """Every team that holds the repository on GitHub, creating one for a group not bound yet.

        All of them, not the best of them: each one's members are people who work on the
        repository, and ranking them would hand the project to one team and hide it from the rest.

        ``current_owner_ids`` are the project's owners this sync may replace: each is asked directly,
        so an owner losing access leaves within the check's TTL rather than the map's.

        ``owner_budget`` is how many owners the project has room for, which is the whole cap for one
        that has no others. Past it nothing is created and nothing is written: a team created for an
        ownership write that is then refused is a team nobody owns anything through.

        Both ingest paths call this only for an instance whose ``sync_teams`` is on, so the switch
        is not read again here.

        Never raises.
        """
        try:
            parts = split_repo_path(repository_path)
            if parts is None:
                logger.warning(
                    "GitHub repository claim %r names no owner/repo; leaving its owners untouched.", repository_path
                )
                return TeamSyncResult(None)
            org, repo = parts
            team_repo = TeamRepository(db)
            bound_teams = await team_repo.find_raw_by_github_org(self._instance_id, org)

            deadline = asyncio.get_running_loop().time() + _GITHUB_RESOLUTION_TIMEOUT
            try:
                async with asyncio.timeout_at(deadline):
                    holders = await self._resolve_repository_holders(org, repo, bound_teams, current_owner_ids)
            except TimeoutError:
                logger.warning(
                    "Resolving the owning teams of %s took longer than %.0fs; leaving them untouched.",
                    repository_path,
                    _GITHUB_RESOLUTION_TIMEOUT,
                )
                return TeamSyncResult(None)

            if holders is None:
                logger.warning(
                    "GitHub could not say which teams hold repository %s; leaving them untouched.", repository_path
                )
                return TeamSyncResult(None)

            if len(holders) > owner_budget:
                logger.warning(
                    "GitHub names %d team(s) holding %s %s but the project has room for %d owner(s); "
                    "leaving its owners untouched rather than creating teams it cannot own through.",
                    len(holders),
                    repository_path,
                    [holder.slug for holder in holders],
                    owner_budget,
                )
                return TeamSyncResult(None)

            logger.info(
                "GitHub team sync for %s: %d team(s) hold it %s.",
                repository_path,
                len(holders),
                [holder.slug for holder in holders],
            )

            # Local writes, outside the deadline: the ownership answer below is what the ingest is
            # here for, and it needs every holder to have a team.
            teams: list[dict[str, Any]] = []
            for holder in holders:
                team = holder.team or await self._team_for_github_group(team_repo, org, holder.team_id, holder.slug)
                if team is None:
                    return TeamSyncResult(None)
                teams.append(team)
            user_repo = UserRepository(db)
            members: list[list[TeamMember] | None] = [None] * len(holders)
            try:
                # The same deadline, so the reads and the member listing and profile read per team
                # share one budget instead of each getting a whole one.
                async with asyncio.timeout_at(deadline):
                    for index, holder in enumerate(holders):
                        members[index] = await self._resolve_holder_members(user_repo, org, repo, holder)
            except TimeoutError:
                logger.warning(
                    "Reading the members of the %d team(s) holding %s did not finish inside the %.0fs "
                    "resolution budget; those not read keep their stored members, and every team still "
                    "follows its GitHub name and slug.",
                    len(holders),
                    repository_path,
                    _GITHUB_RESOLUTION_TIMEOUT,
                )
            # Only the reads are bounded: cancelling a write would leave the team half-refreshed.
            for holder, team, team_members in zip(holders, teams, members, strict=True):
                await self._refresh_team(team_repo, org, holder, team, team_members)
            return TeamSyncResult([str(team["_id"]) for team in teams])

        except Exception as e:
            logger.exception(
                "Error syncing GitHub teams for repository %s: %s: %s",
                repository_path,
                type(e).__name__,
                e,
            )
            return TeamSyncResult(None)

    async def get_pull_requests_for_commit(self, owner: str, repo: str, commit_sha: str) -> list[GitHubPullRequest]:
        """Pull requests associated with a commit, retrying via the head parent when it is a merge commit."""
        pull_requests = await self._pull_requests_for_sha(owner, repo, commit_sha)
        if pull_requests:
            return pull_requests

        # A `pull_request` workflow checks out an ephemeral test-merge commit that GitHub associates with
        # no pull request (HTTP 200 and an empty list, never a 404); its parents[1] is the PR head.
        head_sha = await self._merge_commit_head_parent(owner, repo, commit_sha)
        if head_sha:
            pull_requests = await self._pull_requests_for_sha(owner, repo, head_sha)
            if pull_requests:
                logger.info(
                    "Resolved %s/%s commit %s to pull request(s) %s via merge-commit head parent %s",
                    owner,
                    repo,
                    commit_sha,
                    [pr.number for pr in pull_requests],
                    head_sha,
                )
                return pull_requests

        logger.info(
            "No pull request found for %s/%s commit %s (head parent tried: %s)",
            owner,
            repo,
            commit_sha,
            head_sha or "none",
        )
        return []

    async def _pull_requests_for_sha(self, owner: str, repo: str, sha: str) -> list[GitHubPullRequest]:
        endpoint = f"/repos/{owner}/{repo}/commits/{sha}/pulls"
        response = await self._api_get(endpoint)
        if response is None or not response_ok("GitHub", endpoint, response):
            return []
        return [GitHubPullRequest(**pr) for pr in response.json()]

    async def _merge_commit_head_parent(self, owner: str, repo: str, commit_sha: str) -> str | None:
        """Second parent of a two-parent merge commit. Parent order is a git convention, not an API guarantee."""
        endpoint = f"/repos/{owner}/{repo}/commits/{commit_sha}"
        response = await self._api_get(endpoint)
        if response is None or not response_ok("GitHub", endpoint, response):
            return None
        parents = response.json().get("parents") or []
        if len(parents) != 2:
            return None
        head_sha = parents[1].get("sha")
        return str(head_sha) if head_sha else None

    async def get_pull_request_comments(self, owner: str, repo: str, pr_number: int) -> list[GitHubIssueComment]:
        """Issue comments on a pull request, uncapped so an old scan comment is never missed and duplicated."""
        comments = await self._api_get_paginated(f"/repos/{owner}/{repo}/issues/{pr_number}/comments", max_pages=None)
        return [GitHubIssueComment(**c) for c in comments] if comments else []

    async def post_pull_request_comment(self, owner: str, repo: str, pr_number: int, body: str) -> bool:
        """Post a comment on a pull request."""
        response = await self._api_post(
            f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
            json_data={"body": body},
        )
        if response:
            if response.status_code == 201:
                return True
            logger.error(f"Failed to post PR comment: {response.status_code} - {response.text}")
        return False

    async def update_pull_request_comment(self, owner: str, repo: str, comment_id: int, body: str) -> bool:
        """Update an existing pull-request comment."""
        response = await self._api_patch(
            f"/repos/{owner}/{repo}/issues/comments/{comment_id}",
            json_data={"body": body},
        )
        if response:
            if response.status_code == 200:
                return True
            logger.error(f"Failed to update PR comment: {response.status_code} - {response.text}")
        return False

    async def _get_jwks_uri(self) -> str:
        """Resolve the JWKS URI: well-known endpoint for github.com, OIDC discovery for GHES."""
        cache_key = self._get_cache_key("jwks_uri")

        cached_uri = await cache_service.get(cache_key)
        if cached_uri:
            result: str = cached_uri
            return result

        if "token.actions.githubusercontent.com" in self.base_url:
            await cache_service.set(cache_key, _GITHUB_COM_JWKS_URI, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
            return _GITHUB_COM_JWKS_URI

        async with InstrumentedAsyncClient("GitHub OIDC", timeout=10.0) as client:
            try:
                response = await client.get(f"{self.base_url}/.well-known/openid-configuration")
                if response.status_code == 200:
                    config = response.json()
                    jwks_uri: str | None = config.get("jwks_uri")
                    if jwks_uri:
                        await cache_service.set(cache_key, jwks_uri, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
                        return jwks_uri
            except Exception as e:
                logger.warning(f"Error fetching GitHub OIDC discovery: {e}")

        fallback_uri = f"{self.base_url}/.well-known/jwks"
        await cache_service.set(cache_key, fallback_uri, ttl_seconds=GITHUB_JWKS_URI_CACHE_TTL)
        return fallback_uri

    async def get_jwks(self) -> dict | None:
        """Fetch and Redis-cache the JWKS from GitHub."""
        cache_key = self._get_cache_key("jwks")

        cached_jwks = await cache_service.get(cache_key)
        if cached_jwks:
            result_jwks: dict[Any, Any] = cached_jwks
            return result_jwks

        jwks_uri = await self._get_jwks_uri()
        async with InstrumentedAsyncClient("GitHub JWKS", timeout=10.0) as client:
            try:
                response = await client.get(jwks_uri)
                if response.status_code == 200:
                    jwks: dict[Any, Any] = response.json()
                    await cache_service.set(cache_key, jwks, ttl_seconds=GITHUB_JWKS_CACHE_TTL)
                    return jwks

                logger.error("Failed to fetch GitHub JWKS")
            except Exception as e:
                logger.exception("Error fetching GitHub JWKS: %s", e)
        return {}

    async def _invalidate_jwks_cache(self) -> None:
        """Invalidate the JWKS cache to force a refresh on next request."""
        cache_key = self._get_cache_key("jwks")
        await cache_service.delete(cache_key)

    async def validate_oidc_token(self, token: str) -> GitHubOIDCPayload | None:
        """Validate a GitHub Actions OIDC JWT, refreshing JWKS on key rotation."""
        return await _validate_oidc_token(
            token=token,
            get_jwks=self.get_jwks,
            invalidate_cache=self._invalidate_jwks_cache,
            issuer=self.base_url,
            # `or None` normalizes "" -> None so unconfigured instances fail the audience check closed.
            audience=self.instance.oidc_audience or None,
            payload_model=GitHubOIDCPayload,
            provider_name="GitHub",
        )
