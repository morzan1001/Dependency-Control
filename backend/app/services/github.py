import asyncio
import logging
import urllib.parse
import weakref
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, NamedTuple

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError

from app.core.cache import cache_service
from app.core.constants import (
    GITHUB_JWKS_CACHE_TTL,
    GITHUB_JWKS_URI_CACHE_TTL,
    GITHUB_ORG_REPO_MAP_CACHE_TTL,
    GITHUB_TEAM_SYNC_CACHE_TTL,
    MAX_PROJECT_TEAMS,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
)
from app.core.http_utils import InstrumentedAsyncClient
from app.models.github_api import GitHubIssueComment, GitHubOIDCPayload, GitHubPullRequest
from app.models.github_instance import GitHubInstance
from app.models.team import Team, TeamMember
from app.repositories import TeamRepository, UserRepository
from app.services.oidc_utils import validate_oidc_token as _validate_oidc_token

logger = logging.getLogger(__name__)

_GITHUB_COM_JWKS_URI = "https://token.actions.githubusercontent.com/.well-known/jwks"


_GITHUB_API_TIMEOUT = 10.0

# The resolution runs inside the ingest request. The per-team checks are concurrent, so this bounds
# the whole step rather than one call, and a GitHub that answers slowly costs an ingest this much once.
_GITHUB_RESOLUTION_TIMEOUT = 30.0

_DEFAULT_ACCEPT = "application/vnd.github+json"
# Without this media type the team/repository check answers 204, and "holds it" stops being the
# 200 the caller tests for.
_REPOSITORY_ACCEPT = "application/vnd.github.v3.repository+json"

# One request per team of the organisation, and the largest one here has 204 of them. Run in
# sequence they would outlast the resolution budget; this many at a time finishes the walk well
# inside it and stays far below the hundred concurrent requests GitHub tolerates.
_GITHUB_ORG_WALK_CONCURRENCY = 16

# The walk's own share of the resolution budget. Exceeding it is recorded rather than abandoned, so
# the next ingest reads the failure from the cache instead of paying the whole walk again.
_GITHUB_ORG_WALK_TIMEOUT = 15.0

# A waiter has to outlast the walk it is waiting for, or it gives up and walks as well — which is
# the stampede the lock exists to prevent.
_GITHUB_ORG_WALK_LOCK_WAIT = 18.0

# The walk is cached under a field of its own: the locking helper stores a bare {} for a fetch that
# failed, and an empty map read back from that would say the organisation's teams hold nothing.
_ORG_REPO_MAP_FIELD = "repositories"

# Write access or better. Read access is not ownership: a group holding every repository of the
# organisation on pull would otherwise own the whole estate.
_WRITE_PERMISSIONS = ("push", "maintain", "admin")

_AUTO_TEAM_NAME_PREFIX = "GitHub Team:"

# A GitHub slug carries a prefix the same team's Dependency Control name does not.
_ADOPTION_PREFIXES = ("team-", "team_")

_org_walk_gates: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = (
    weakref.WeakKeyDictionary()
)


def _org_walk_gate() -> asyncio.Semaphore:
    """The walk's concurrency limit, shared by every walk running in this process.

    One workflow run fans out into many ingests, so a gate held by a single walk bounds nothing:
    eight concurrent ingests measured a peak of 112 requests in flight against a limit of 16.
    """
    loop = asyncio.get_running_loop()
    gate = _org_walk_gates.get(loop)
    if gate is None:
        gate = asyncio.Semaphore(_GITHUB_ORG_WALK_CONCURRENCY)
        _org_walk_gates[loop] = gate
    return gate


def _adoption_key(name: str) -> str:
    """The form two names are compared in before a team is created: lower case, without a leading
    "team-", letters and digits only. "team-shangri-llama" and "Shangri Llama" are one team under it."""
    lowered = name.strip().lower()
    for prefix in _ADOPTION_PREFIXES:
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix) :]
            break
    return "".join(character for character in lowered if character.isalnum())


def _team_writes_to(repository: dict[str, Any]) -> bool | None:
    """Whether the team's access to the repository is write or better; None when the listing did not
    say, which must not read as read-only and retire the owners of a whole organisation."""
    permissions = repository.get("permissions")
    if not isinstance(permissions, dict):
        return None
    return any(bool(permissions.get(level)) for level in _WRITE_PERMISSIONS)


def _auto_team_name(org: str, slug: str) -> str:
    """The name a team gets while nobody has renamed it; the prefix is what marks it as ours to set."""
    return f"{_AUTO_TEAM_NAME_PREFIX} {org}/{slug}"


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
                "parent_slug": _team_slug(parent),
                "parent_name": str(parent["name"]) if parent.get("name") else None,
            }
        )
    return options


class GitHubTeamSyncResult(NamedTuple):
    """Every Dependency Control team GitHub says holds the repository.

    ``team_ids`` is None when GitHub could not be asked, which is not the same answer as the empty
    list: the first leaves the project's GitHub owners alone, the second retires them.
    """

    team_ids: list[str] | None


class _HolderBinding(NamedTuple):
    """A GitHub team holding the repository, before its Dependency Control team is settled.

    ``team`` carries the bound team where one is bound, and None for a group whose team is still to
    be adopted or created — which happens only once the whole set is known to fit the project.
    """

    team_id: int
    slug: str
    team: dict[str, Any] | None


class _RepositoryHolder(NamedTuple):
    """A team holding the repository: its Dependency Control document and how to address it."""

    team: dict[str, Any]
    team_id: int
    slug: str


class GitHubService:
    """OIDC token validation and API operations for github.com and GHES instances."""

    def __init__(self, github_instance: GitHubInstance):
        self.instance = github_instance
        self.base_url = github_instance.url.rstrip("/")
        self._cache_key_prefix = f"gh_instance:{github_instance.id}"

        # Derive API URL from github_url. Match on the parsed host (not a
        # substring): hostnames like "github.company.com" or
        # "github.com.mycorp.internal" contain "github.com" but are GHES
        # instances that must NOT have their PAT sent to public api.github.com.
        github_url = (github_instance.github_url or "").rstrip("/")
        host = (urllib.parse.urlsplit(github_url).hostname or "").lower()
        if not github_url or host in ("github.com", "www.github.com"):
            self.api_url = "https://api.github.com"
        else:
            # GHES: https://{host}/api/v3
            self.api_url = f"{github_url}/api/v3"

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
        if not self.instance.access_token:
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
        if not self.instance.access_token:
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
        if not self.instance.access_token:
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

    async def _api_get_paginated(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        max_pages: int | None = 10,
    ) -> list[dict[str, Any]] | None:
        """Paginated GET via GitHub's Link header; returns all items or None on failure.

        ``max_pages=None`` fetches all pages uncapped; a hit finite cap logs a
        truncation WARNING.
        """
        if not self.instance.access_token:
            return None

        all_items: list[dict[str, Any]] = []
        page = 1
        per_page = 100

        try:
            async with self._api_client() as client:
                while max_pages is None or page <= max_pages:
                    request_params = {**(params or {}), "page": page, "per_page": per_page}
                    response = await client.get(
                        f"{self.api_url}{endpoint}",
                        headers=self._get_auth_headers(),
                        params=request_params,
                    )

                    if response.status_code != 200:
                        logger.error(f"GitHub API GET {endpoint} page {page} failed: {response.status_code}")
                        return None

                    items = response.json()
                    if not items:
                        break

                    all_items.extend(items)

                    if 'rel="next"' not in response.headers.get("link", ""):
                        break
                    if self._cap_reached(endpoint, page, max_pages, len(all_items)):
                        break

                    page += 1

        except Exception as e:
            logger.exception("GitHub API paginated GET %s failed: %s", endpoint, e)
            return None

        return all_items

    @staticmethod
    def _cap_reached(endpoint: str, page: int, max_pages: int | None, item_count: int) -> bool:
        """True (and logs a WARNING) when a finite cap is hit while the Link header still offers a next page."""
        if max_pages is None or page < max_pages:
            return False
        logger.warning(
            "GitHub API GET %s hit the pagination cap of %d page(s) (%d items) but the Link header "
            'still offers rel="next". Result is TRUNCATED.',
            endpoint,
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
        response = await self._api_get(f"/repos/{owner}/{repo}")
        if response and response.status_code == 200:
            branch = response.json().get("default_branch")
            return str(branch) if branch else None
        return None

    async def _get_cached_list(self, cache_key: str) -> list[dict[str, Any]] | None:
        cached: list[dict[str, Any]] | None = await cache_service.get(cache_key)
        return cached

    async def _get_cached_all_pages(self, cache_key: str, endpoint: str) -> list[dict[str, Any]] | None:
        cached = await self._get_cached_list(cache_key)
        if cached is not None:
            return cached

        items = await self._api_get_paginated(endpoint, max_pages=None)
        if items is None:
            return None
        await cache_service.set(cache_key, items, ttl_seconds=GITHUB_TEAM_SYNC_CACHE_TTL)
        return items

    async def get_team_repository(self, org: str, team_slug: str, owner: str, repo: str) -> bool | None:
        """Whether one team holds one repository; None when GitHub did not answer.

        Answers on a read-only organisation token, which asking the repository for its teams
        cannot: that requires the admin role on every single repository.
        """
        cache_key = self._get_cache_key(f"team_repo:{org}/{team_slug}:{owner}/{repo}")
        # Wrapped in a document because a bare cached False is indistinguishable from a miss.
        cached: dict[str, Any] | None = await cache_service.get(cache_key)
        if cached is not None:
            return bool(cached["has_repo"])

        endpoint = f"/orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
        response = await self._api_get(endpoint, accept=_REPOSITORY_ACCEPT)
        if response is None:
            return None

        if response.status_code == 200:
            has_repo = True
        elif response.status_code == 404:
            has_repo = False
        else:
            # A refusal read as "this team does not hold the repository" would retire the team
            # from every project it owns.
            logger.warning("GitHub API GET %s returned HTTP %d", endpoint, response.status_code)
            return None

        await cache_service.set(cache_key, {"has_repo": has_repo}, ttl_seconds=GITHUB_TEAM_SYNC_CACHE_TTL)
        return has_repo

    async def get_org_teams(self, org: str) -> list[dict[str, Any]] | None:
        """Every team of an organisation, with the parent that tells two same-named ones apart."""
        return await self._get_cached_all_pages(self._get_cache_key(f"org_teams:{org}"), f"/orgs/{org}/teams")

    async def _list_team_repositories(self, org: str, slug: str) -> list[str] | None:
        """The full names one team may write to, lower-cased; None when a page went unanswered or
        did not say what the team's access is.

        A team with mere read access is not an owner: the people who can change the code are.
        """
        async with _org_walk_gate():
            repos = await self._api_get_paginated(f"/orgs/{org}/teams/{slug}/repos", max_pages=None)
        if repos is None:
            return None

        written: list[str] = []
        for repository in repos:
            writes = _team_writes_to(repository)
            if writes is None:
                logger.warning(
                    "GitHub listed a repository of team %s/%s without the team's permissions; the "
                    "organisation's holders stay undetermined.",
                    org,
                    slug,
                )
                return None
            if writes and (full_name := repository.get("full_name")):
                written.append(str(full_name).lower())
        return written

    async def _fetch_org_repository_map(
        self, org: str, org_teams: list[dict[str, Any]]
    ) -> dict[str, list[int]] | None:
        """Walk every team of the organisation. None when one of them went unanswered.

        Half a walk names the wrong holders rather than fewer of them: the teams it did not reach
        would read as teams that hold nothing, so a partial result is no result.
        """
        addressed = [
            (team_id, slug)
            for team in org_teams
            if (team_id := _team_id(team)) is not None and (slug := _team_slug(team)) is not None
        ]
        listings = await asyncio.gather(*(self._list_team_repositories(org, slug) for _id, slug in addressed))

        repo_map: dict[str, list[int]] = {}
        for (team_id, _slug), repositories in zip(addressed, listings, strict=True):
            if repositories is None:
                return None
            for full_name in repositories:
                repo_map.setdefault(full_name, []).append(team_id)
        return repo_map

    async def _walk_org_repository_map(self, org: str, org_teams: list[dict[str, Any]]) -> dict[str, Any] | None:
        """The walk wrapped for the cache; None when it failed or outlasted its own budget.

        Wrapped in a field rather than cached bare because the locking helper stores a failed fetch
        as ``{}``, and that unwrapped would read as an organisation whose teams hold nothing.
        """
        try:
            repo_map = await asyncio.wait_for(
                self._fetch_org_repository_map(org, org_teams), _GITHUB_ORG_WALK_TIMEOUT
            )
        except TimeoutError:
            logger.warning(
                "Walking the %d team(s) of GitHub organisation %s took longer than %.0fs; the "
                "organisation stays undetermined until the entry expires, rather than being walked "
                "again by every ingest.",
                len(org_teams),
                org,
                _GITHUB_ORG_WALK_TIMEOUT,
            )
            return None
        return None if repo_map is None else {_ORG_REPO_MAP_FIELD: repo_map}

    async def get_org_repository_map(self, org: str, org_teams: list[dict[str, Any]]) -> dict[str, list[int]] | None:
        """Repository full name -> the teams of ``org`` holding it; None when the walk did not finish.

        Asking the repository which teams hold it needs the admin role on that repository, so the
        only answer a read-only organisation token can give costs a request per team. One walk per
        organisation and TTL, behind the stampede lock: the jobs of one workflow run arrive
        together, and eight of them walking a 204-team organisation is 1632 of 5000 hourly requests.
        """
        cache_key = self._get_cache_key(f"org_repo_map:{org}")
        cached = await cache_service.get_or_fetch_with_lock(
            cache_key,
            lambda: self._walk_org_repository_map(org, org_teams),
            ttl_seconds=GITHUB_ORG_REPO_MAP_CACHE_TTL,
            max_wait_seconds=_GITHUB_ORG_WALK_LOCK_WAIT,
        )
        repositories = cached.get(_ORG_REPO_MAP_FIELD) if isinstance(cached, dict) else None
        return repositories if isinstance(repositories, dict) else None

    async def count_org_teams(self, org: str) -> int | None:
        """How many teams the token can read in an organisation; None when the API refuses.

        Uncached, unlike ``get_org_teams``: a connection test must observe the token as it is now,
        not as it was five minutes ago.
        """
        teams = await self._api_get_paginated(f"/orgs/{org}/teams", max_pages=None)
        return None if teams is None else len(teams)

    async def get_team_members(self, org: str, team_slug: str, team_id: int) -> list[dict[str, Any]] | None:
        """Logins tagged with their role. Cached on the numeric id: the slug is renameable."""
        cache_key = self._get_cache_key(f"team_members:{org}/{team_id}")
        cached = await self._get_cached_list(cache_key)
        if cached is not None:
            return cached

        endpoint = f"/orgs/{org}/teams/{team_slug}/members"
        members: list[dict[str, Any]] = []
        # The endpoint returns plain user objects, so the role can only come from the query.
        for role in ("maintainer", "member"):
            page = await self._api_get_paginated(endpoint, params={"role": role}, max_pages=None)
            if page is None:
                return None
            members.extend({"login": user["login"], "role": role} for user in page if user.get("login"))

        await cache_service.set(cache_key, members, ttl_seconds=GITHUB_TEAM_SYNC_CACHE_TTL)
        return members

    async def get_viewer_organisations(self) -> list[dict[str, Any]] | None:
        """Organisations the token's own identity belongs to. Uncached: a connection test must
        observe the token as it is now, not as it was five minutes ago."""
        return await self._api_get_paginated("/user/orgs", max_pages=None)

    async def get_user_public_email(self, login: str) -> str | None:
        """The public profile email, or None when the user hides it. Cached per login: this is the
        one per-member call of a sync, and the jobs of one workflow run must not repeat it."""
        cache_key = self._get_cache_key(f"user_email:{login}")
        # "" is the stored "no public email": a cached None reads back as a miss, and the bots that
        # never resolve are exactly the logins not worth asking about twice.
        cached: str | None = await cache_service.get(cache_key)
        if cached is not None:
            return cached or None

        response = await self._api_get(f"/users/{login}")
        if response is None:
            return None
        if response.status_code == 200:
            profile_email = response.json().get("email")
            email = str(profile_email) if profile_email else ""
        elif response.status_code == 404:
            email = ""
        else:
            # A refusal read as "no public email" would silently disable email matching for every
            # member; caching it would extend that to every later job of the run.
            logger.warning("GitHub API GET /users/%s failed: %s", login, response.status_code)
            return None

        await cache_service.set(cache_key, email, ttl_seconds=GITHUB_TEAM_SYNC_CACHE_TTL)
        return email or None

    async def _find_user_for_github_member(self, login: str, user_repo: UserRepository) -> dict[str, Any] | None:
        """Resolve a GitHub login to an EXISTING local user: username first, then the public email."""
        user = await user_repo.get_raw_by_username(login)
        if user:
            return user
        email = await self.get_user_public_email(login)
        if email:
            # Case-insensitive: the OIDC-login email may differ in case from the profile one.
            return await user_repo.get_raw_by_email_ci(email)
        return None

    async def _build_team_members(
        self,
        members: list[dict[str, Any]],
        user_repo: UserRepository,
    ) -> tuple[list[TeamMember], int]:
        """Map GitHub members onto existing local users, tagged source="github", plus the unresolved count."""
        resolved: dict[str, TeamMember] = {}
        unresolved = 0
        for member in members:
            login = member["login"]
            user = await self._find_user_for_github_member(login, user_repo)
            if not user:
                # Sync never creates users; a real member is added on their next sync after
                # logging in via OIDC.
                unresolved += 1
                logger.debug("Skipping GitHub member that resolved to no local user (login=%s).", login)
                continue
            role = TEAM_ROLE_ADMIN if member.get("role") == "maintainer" else TEAM_ROLE_MEMBER
            user_id = str(user.get("_id", user.get("id")))
            # Two logins can resolve to one local user. A duplicate entry breaks add_member's $ne
            # guard, and the next sync's last-wins merge would silently demote the admin entry.
            previous = resolved.get(user_id)
            if previous is not None and previous.role == TEAM_ROLE_ADMIN:
                continue
            resolved[user_id] = TeamMember(user_id=user_id, role=role, source="github")
        return list(resolved.values()), unresolved

    @staticmethod
    def _merge_team_members(
        existing_members: list[dict[str, Any]],
        github_members: list[TeamMember],
    ) -> list[dict[str, Any]]:
        """Keep manual members; replace the github-sourced subset so departed members disappear."""
        merged: dict[str, dict[str, Any]] = {}
        # Untagged members default to manual so pre-existing members are preserved.
        for raw in existing_members:
            if raw.get("source", "manual") != "github":
                merged[raw["user_id"]] = {**raw, "source": "manual"}
        for member in github_members:
            merged[member.user_id] = member.model_dump()
        return list(merged.values())

    @staticmethod
    def _renamed_fields(team: dict[str, Any], org: str, team_slug: str) -> dict[str, Any]:
        """The name to follow GitHub with, while the team still carries the generated one.

        A team its owner renamed keeps that name for good: only the prefix marks a name as ours.
        """
        current = str(team.get("name") or "")
        generated = _auto_team_name(org, team_slug)
        if not current.startswith(_AUTO_TEAM_NAME_PREFIX) or current == generated:
            return {}
        return {"name": generated, "description": _auto_team_description(org, team_slug)}

    async def _refresh_team(
        self,
        team_repo: TeamRepository,
        team: dict[str, Any],
        org: str,
        team_slug: str,
        team_members: list[TeamMember] | None,
    ) -> None:
        """Write what GitHub has since changed about a holding team.

        ``team_members`` is None to leave the stored members alone, which the rename must not hang
        on: barely a login resolves here, so a name would otherwise never follow a renamed team.
        """
        updates: dict[str, Any] = self._renamed_fields(team, org, team_slug)
        if team_members is not None:
            updates["members"] = self._merge_team_members(team.get("members") or [], team_members)
        if team.get("github_team_slug") != team_slug:
            # The binding is the numeric team id, so a renamed slug has to follow it.
            updates["github_team_slug"] = team_slug
        if not updates:
            return
        await team_repo.update(team["_id"], {**updates, "updated_at": datetime.now(timezone.utc)})

    async def _adopt_unbound_team(
        self,
        team_repo: TeamRepository,
        org: str,
        team_id: int,
        slug: str,
    ) -> dict[str, Any] | None:
        """A team the owner already has under this group's name, bound to it rather than duplicated.

        Only a team no provider binding claims is taken: one already synced elsewhere would have
        two syncs replacing each other's members, and one bound to another group or instance is
        somebody else's. Two teams of the same name are no answer, so neither of them is taken.
        """
        key = _adoption_key(slug)
        if not key:
            return None
        candidates = [
            team for team in await team_repo.find_raw_unbound() if _adoption_key(str(team.get("name") or "")) == key
        ]
        if not candidates:
            return None
        if len(candidates) > 1:
            logger.warning(
                "GitHub team %s/%s reads as %d existing teams here (%s); creating a team of its own "
                "rather than binding the wrong one.",
                org,
                slug,
                len(candidates),
                [team.get("name") for team in candidates],
            )
            return None

        try:
            adopted = await team_repo.bind_github_team(
                str(candidates[0]["_id"]),
                {
                    "github_instance_id": str(self.instance.id),
                    "github_org": org,
                    "github_team_id": team_id,
                    "github_team_slug": slug,
                },
            )
        except DuplicateKeyError:
            # Another ingest bound this group to a team of its own; that one is the holder.
            return None
        if adopted is None:
            return None
        logger.info(
            "Bound existing team '%s' to GitHub team %s/%s (id=%d) instead of creating a second one.",
            adopted.get("name"),
            org,
            slug,
            team_id,
        )
        return adopted

    async def _team_for_github_group(
        self,
        team_repo: TeamRepository,
        org: str,
        team_id: int,
        slug: str,
    ) -> dict[str, Any]:
        """The Dependency Control team for a GitHub team: the one bound to it, one of the same name,
        or a new one.

        Created even when GitHub names members none of whom resolve: logins here are personal
        handles while usernames are directory ids, so requiring a resolved member — as the GitLab
        sync does — would mean never creating anything. An empty team its owner fills by hand is
        worth more than a group that never appears.
        """
        instance_id = str(self.instance.id)
        existing = await team_repo.get_raw_by_github_team(instance_id, team_id)
        if existing:
            return existing

        adopted = await self._adopt_unbound_team(team_repo, org, team_id, slug)
        if adopted:
            return adopted

        team = Team(
            name=_auto_team_name(org, slug),
            description=_auto_team_description(org, slug),
            github_instance_id=instance_id,
            github_org=org,
            github_team_id=team_id,
            github_team_slug=slug,
        )
        try:
            await team_repo.create(team)
        except DuplicateKeyError:
            # Another repository of the same organisation is being ingested and got here first.
            concurrent = await team_repo.get_raw_by_github_team(instance_id, team_id)
            if concurrent is None:
                raise
            return concurrent
        logger.info("Created team '%s' for GitHub team %s/%s (id=%d).", team.name, org, slug, team_id)
        return team.model_dump(by_alias=True)

    @staticmethod
    def _address_bound_teams(
        org: str,
        owner: str,
        repo: str,
        bound_teams: list[dict[str, Any]],
        slug_map: dict[int, str],
    ) -> list[tuple[dict[str, Any], int, str]] | None:
        """Each bound team with the slug to ask about it, or None when one of them cannot be asked.

        The organisation listing omits the teams the token cannot see, secret ones above all. Skipping
        such a binding would hand the repository to whichever team did answer and report that as a
        determined result, which is the very failure the per-team check exists to avoid.
        """
        addressed = []
        for team in bound_teams:
            team_id = team.get("github_team_id")
            if not isinstance(team_id, int) or (slug := slug_map.get(team_id)) is None:
                logger.warning(
                    "Team %s is bound to GitHub team %s of %s, which the organisation listing does not "
                    "show; the owner of %s/%s stays undetermined until the binding is corrected.",
                    team.get("_id"),
                    team_id,
                    org,
                    owner,
                    repo,
                )
                return None
            addressed.append((team, team_id, slug))
        return addressed

    async def _collect_repository_candidates(
        self,
        org: str,
        owner: str,
        repo: str,
        bound_teams: list[dict[str, Any]],
        slug_map: dict[int, str],
    ) -> list[_HolderBinding] | None:
        """The bound teams that hold the repository. None when a single check went unanswered:
        an incomplete set would retire the owners whose answers are the ones missing.
        """
        addressed = self._address_bound_teams(org, owner, repo, bound_teams, slug_map)
        if addressed is None:
            return None

        accesses = await asyncio.gather(
            *(self.get_team_repository(org, slug, owner, repo) for _team, _team_id, slug in addressed)
        )

        holders: list[_HolderBinding] = []
        for (team, team_id, slug), has_repo in zip(addressed, accesses, strict=True):
            if has_repo is None:
                return None
            if has_repo:
                holders.append(_HolderBinding(team_id, slug, team))
        return holders

    async def _discover_bindings(
        self,
        org: str,
        owner: str,
        repo: str,
        org_teams: list[dict[str, Any]],
        bound_teams: list[dict[str, Any]],
        slug_map: dict[int, str],
    ) -> list[_HolderBinding] | None:
        """The organisation's own groups holding the repository, addressed but not yet created.

        Asked on every sync rather than only when nothing bound holds the repository: a group
        granted access after the first owner was found would otherwise never be seen. The walk it
        reads is cached per organisation, so an ingest pays for it once a TTL.
        """
        if not self.instance.sync_teams:
            return []

        repo_map = await self.get_org_repository_map(org, org_teams)
        if repo_map is None:
            logger.warning(
                "Could not map the teams of GitHub organisation %s onto its repositories; "
                "leaving %s/%s untouched.",
                org,
                owner,
                repo,
            )
            return None

        bound_ids = {team.get("github_team_id") for team in bound_teams}
        bindings: list[_HolderBinding] = []
        for team_id in repo_map.get(f"{owner}/{repo}".lower(), []):
            if team_id in bound_ids:
                # Already asked about this repository directly, and that answer is the fresher one.
                continue
            slug = slug_map.get(team_id)
            if slug is None:
                # The map outlives the team listing, so a team dissolved since the walk lands here.
                logger.warning(
                    "GitHub team %d holds %s/%s in the cached map of %s but the organisation no longer "
                    "lists it; leaving it out.",
                    team_id,
                    owner,
                    repo,
                    org,
                )
                continue
            bindings.append(_HolderBinding(team_id, slug, None))
        return bindings

    async def _resolve_repository_holders(
        self,
        org: str,
        owner: str,
        repo: str,
        bound_teams: list[dict[str, Any]],
    ) -> list[_HolderBinding] | None:
        """Every GitHub team holding the repository, or None when GitHub could not answer for all
        of them. Reads only: nothing is written before the whole set is known."""
        org_teams = await self.get_org_teams(org)
        if org_teams is None:
            logger.warning(
                "Could not list the teams of GitHub organisation %s; leaving %s/%s untouched.", org, owner, repo
            )
            return None

        slug_map = build_team_slug_map(org_teams)
        bound = await self._collect_repository_candidates(org, owner, repo, bound_teams, slug_map)
        if bound is None:
            return None
        discovered = await self._discover_bindings(org, owner, repo, org_teams, bound_teams, slug_map)
        if discovered is None:
            return None
        return [*bound, *discovered]

    async def _materialise_holders(
        self,
        team_repo: TeamRepository,
        org: str,
        bindings: list[_HolderBinding],
    ) -> list[_RepositoryHolder]:
        """Each holding group as the team that owns the project, adopted or created where needed."""
        holders = []
        for binding in bindings:
            team = binding.team or await self._team_for_github_group(team_repo, org, binding.team_id, binding.slug)
            holders.append(_RepositoryHolder(team, binding.team_id, binding.slug))
        return holders

    async def _resolve_holder_members(
        self,
        user_repo: UserRepository,
        org: str,
        holder: _RepositoryHolder,
        repository_path: str,
    ) -> list[TeamMember] | None:
        """The members to store for a holding team, or None to leave the stored ones alone."""
        # An empty list is a team nobody is left in, and its members must go; only None is a failure.
        members = await self.get_team_members(org, holder.slug, holder.team_id)
        if members is None:
            logger.warning(
                "Failed to fetch members for GitHub team %s/%s (id=%d) while syncing %s. Skipping member sync.",
                org,
                holder.slug,
                holder.team_id,
                repository_path,
            )
            return None

        team_members, unresolved = await self._build_team_members(members, user_repo)
        if unresolved and not team_members:
            # A token that lost profile access resolves nobody; writing that would strip the
            # whole github subset and read as a team everyone left.
            logger.warning(
                "Resolved 0 of %d members of GitHub team %s/%s (id=%d) while syncing %s; "
                "leaving the existing members untouched.",
                unresolved,
                org,
                holder.slug,
                holder.team_id,
                repository_path,
            )
            return None
        return team_members

    async def _sync_holder(
        self,
        team_repo: TeamRepository,
        user_repo: UserRepository,
        org: str,
        holder: _RepositoryHolder,
        repository_path: str,
    ) -> None:
        """Refresh one holding team. Best effort: the team owns the project either way."""
        members = await self._resolve_holder_members(user_repo, org, holder, repository_path)
        await self._refresh_team(team_repo, holder.team, org, holder.slug, members)

    async def sync_team_from_github(
        self,
        db: AsyncIOMotorDatabase,
        org: str,
        repository_path: str,
        *,
        owner_budget: int = MAX_PROJECT_TEAMS,
    ) -> GitHubTeamSyncResult:
        """Every team that holds the repository on GitHub, creating one for a group not bound yet.

        All of them, not the best of them: each one's members are people who work on the
        repository, and ranking them would hand the project to one team and hide it from the rest.

        ``owner_budget`` is how many owners the project has room for, which is the whole cap for one
        that has no others. Past it nothing is created and nothing is written: a team created for an
        ownership write that is then refused is a team nobody owns anything through.

        Never raises.
        """
        try:
            owner, _, repo = repository_path.partition("/")
            team_repo = TeamRepository(db)
            bound_teams = await team_repo.find_raw_by_github_org(str(self.instance.id), org)
            if not bound_teams and not self.instance.sync_teams:
                # Determined, not unknown: with nothing bound and nothing creatable, no GitHub team
                # owns anything here, and the organisation is not worth a request.
                logger.info(
                    "No team is bound to GitHub organisation %s and creating one is off; "
                    "%s keeps no GitHub owner.",
                    org,
                    repository_path,
                )
                return GitHubTeamSyncResult([])

            try:
                # Only the reads are bounded: cancelling them costs nothing, while cancelling a
                # half-written set of teams would leave teams behind that own nothing.
                bindings = await asyncio.wait_for(
                    self._resolve_repository_holders(org, owner, repo, bound_teams),
                    _GITHUB_RESOLUTION_TIMEOUT,
                )
            except TimeoutError:
                logger.warning(
                    "Resolving the owning teams of %s took longer than %.0fs; leaving them untouched.",
                    repository_path,
                    _GITHUB_RESOLUTION_TIMEOUT,
                )
                return GitHubTeamSyncResult(None)

            if bindings is None:
                logger.warning(
                    "GitHub could not say which teams hold repository %s; leaving them untouched.", repository_path
                )
                return GitHubTeamSyncResult(None)

            if len(bindings) > owner_budget:
                logger.warning(
                    "GitHub names %d team(s) holding %s %s but the project has room for %d owner(s); "
                    "leaving its owners untouched rather than creating teams it cannot own through.",
                    len(bindings),
                    repository_path,
                    [binding.slug for binding in bindings],
                    owner_budget,
                )
                return GitHubTeamSyncResult(None)

            logger.info(
                "GitHub team sync for %s: %d team(s) hold it %s.",
                repository_path,
                len(bindings),
                [binding.slug for binding in bindings],
            )

            holders = await self._materialise_holders(team_repo, org, bindings)
            user_repo = UserRepository(db)
            for holder in holders:
                await self._sync_holder(team_repo, user_repo, org, holder, repository_path)
            return GitHubTeamSyncResult([str(holder.team["_id"]) for holder in holders])

        except Exception as e:
            logger.exception(
                "Error syncing GitHub teams for repository %s: %s: %s",
                repository_path,
                type(e).__name__,
                e,
            )
            return GitHubTeamSyncResult(None)

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
        if response is None or not self._ok(endpoint, response):
            return []
        return [GitHubPullRequest(**pr) for pr in response.json()]

    async def _merge_commit_head_parent(self, owner: str, repo: str, commit_sha: str) -> str | None:
        """Second parent of a two-parent merge commit. Parent order is a git convention, not an API guarantee."""
        endpoint = f"/repos/{owner}/{repo}/commits/{commit_sha}"
        response = await self._api_get(endpoint)
        if response is None or not self._ok(endpoint, response):
            return None
        parents = response.json().get("parents") or []
        if len(parents) != 2:
            return None
        head_sha = parents[1].get("sha")
        return str(head_sha) if head_sha else None

    @staticmethod
    def _ok(endpoint: str, response: httpx.Response) -> bool:
        """True for 200. A rejected read must not be mistaken for an empty one, so a non-200 is logged here."""
        if response.status_code == 200:
            return True
        logger.warning("GitHub API GET %s returned HTTP %d", endpoint, response.status_code)
        return False

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

    async def _get_jwks_uri(self) -> str | None:
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

        async with InstrumentedAsyncClient("GitHub JWKS", timeout=10.0) as client:
            try:
                jwks_uri = await self._get_jwks_uri()

                if jwks_uri:
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
