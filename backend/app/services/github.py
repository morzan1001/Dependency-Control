import asyncio
import logging
import urllib.parse
from collections.abc import Awaitable, Callable
from contextlib import aclosing
from datetime import datetime, timezone
from functools import partial
from typing import Any, NamedTuple

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.cache import cache_service
from app.core.constants import (
    GITHUB_API_URL,
    GITHUB_ORG_REPO_MAP_CACHE_TTL,
    GITHUB_TEAM_SYNC_CACHE_TTL,
    GITHUB_USER_EMAIL_CACHE_TTL,
    MAX_PROJECT_TEAMS,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
    TEAM_SOURCE_GITHUB,
)
from app.core.http_utils import quota_lifts_at
from app.models.github_api import GitHubIssueComment, GitHubOIDCPayload, GitHubPullRequest
from app.models.github_instance import GITHUB_SHARED_OIDC_ISSUER, GitHubInstance
from app.models.team import GitHubTeamBinding, Team, TeamMember, TeamSyncResult, binding_of
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.schemas.github_instance import GitHubOrgTeam
from app.services.git_provider import GitProviderService, ResponseHooks, json_document, request_gate
from app.services.oidc_utils import discover_jwks_uri

logger = logging.getLogger(__name__)

_GITHUB_COM_JWKS_URI = "https://token.actions.githubusercontent.com/.well-known/jwks"

_PUBLIC_GITHUB_WEB_HOSTS = frozenset({"github.com", "www.github.com"})


# One deadline over the whole resolution, which runs inside the ingest request, so slowness costs this once.
_GITHUB_RESOLUTION_TIMEOUT = 30.0

_DEFAULT_ACCEPT = "application/vnd.github+json"
# Without this media type the team/repository check answers 204 without the body that reports the permission.
_REPOSITORY_ACCEPT = "application/vnd.github.v3.repository+json"

# The walk's share of the resolution budget, from its first gated listing; a timeout is cached as a failure.
_GITHUB_ORG_WALK_TIMEOUT = 15.0

# A failed fetch is cached as a bare {} for an hour; the wrapper keeps a real None answer distinct.
_CACHED_FIELD = "value"

# Read access is not ownership: a group pulling every repository would otherwise own the whole estate.
_WRITE_PERMISSIONS = ("push", "maintain", "admin")

_GITHUB_TEAM_ROLES = (("maintainer", TEAM_ROLE_ADMIN), ("member", TEAM_ROLE_MEMBER))

# Per pod is enough: branch sync, which builds a service per project, runs on one pod under its lock.
_rate_limit_holds: dict[str, datetime] = {}


def split_repo_path(path: str | None) -> tuple[str, str] | None:
    owner, _, repo = (path or "").partition("/")
    return (owner, repo) if owner and repo else None


def _team_writes_to(repository: dict[str, Any]) -> bool | None:
    """None when the listing did not say, which must not read as read-only and retire a whole organisation's owners."""
    permissions = repository.get("permissions")
    if not isinstance(permissions, dict):
        return None
    return any(bool(permissions.get(level)) for level in _WRITE_PERMISSIONS)


def _auto_team_name(org: str, slug: str) -> str:
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
    """A stored slug would address the wrong team after a rename, so calls use the listing's current slug."""
    return {
        team_id: slug
        for team in org_teams
        if (team_id := _team_id(team)) is not None and (slug := _team_slug(team)) is not None
    }


def build_org_team_options(org_teams: list[dict[str, Any]]) -> list[GitHubOrgTeam]:
    """The parent tells two same-named nested teams apart."""
    options = []
    for team in org_teams:
        team_id = _team_id(team)
        slug = _team_slug(team)
        if team_id is None or slug is None:
            continue
        parent = team.get("parent") or {}
        options.append(
            GitHubOrgTeam(
                id=team_id,
                slug=slug,
                name=str(team.get("name") or slug),
                parent_name=str(parent["name"]) if parent.get("name") else None,
            )
        )
    return options


class _HolderBinding(NamedTuple):
    """team is None until adopted or created, which waits until the whole set is known to fit the project."""

    team_id: int
    slug: str
    team: dict[str, Any] | None


class GitHubCoreRateLimit(NamedTuple):
    """remaining == 0 is what turns every other call into a 403."""

    remaining: int
    reset_at: datetime


def _hostname(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def is_public_github(github_url: str | None, issuer_url: str) -> bool:
    # The parsed host, not a substring: "github.company.com" and "github.com.corp.internal" are GHES.
    if github_url:
        return _hostname(github_url) in _PUBLIC_GITHUB_WEB_HOSTS
    return _hostname(issuer_url) == _hostname(GITHUB_SHARED_OIDC_ISSUER)


def github_api_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": _DEFAULT_ACCEPT, "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class GitHubService(GitProviderService[GitHubInstance, GitHubOIDCPayload]):
    provider = "GitHub"
    _cache_prefix = "github:gh_instance"
    team_provider = TEAM_SOURCE_GITHUB
    _email_field = "email"
    _email_cache_ttl = GITHUB_USER_EMAIL_CACHE_TTL
    _oidc_payload = GitHubOIDCPayload

    def __init__(self, github_instance: GitHubInstance):
        super().__init__(github_instance)
        self.token_rejected = False
        github_url = (github_instance.github_url or "").rstrip("/")
        if is_public_github(github_url, github_instance.url):
            self.api_url = GITHUB_API_URL
        elif github_url:
            self.api_url = f"{github_url}/api/v3"
        else:
            # A GHES issuer without a web URL names no API host; its token is sent nowhere.
            self.api_url = None

    @property
    def rate_limited_until(self) -> datetime | None:
        lifts_at = _rate_limit_holds.get(self.instance_id)
        return lifts_at if lifts_at is not None and datetime.now(timezone.utc) < lifts_at else None

    def _token_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": _DEFAULT_ACCEPT}

    def _can_call(self) -> bool:
        return super()._can_call() and self.rate_limited_until is None

    def _response_hooks(self) -> ResponseHooks:
        return {"response": [self._note_rate_limit, self._note_token_rejection]}

    async def _note_token_rejection(self, response: httpx.Response) -> None:
        """GitHub answers an expired or revoked token with 401, and a missing scope or a spent budget with 403."""
        if response.status_code == 401:
            self.token_rejected = True

    async def _note_rate_limit(self, response: httpx.Response) -> None:
        """Async only because httpx.AsyncClient awaits its event hooks."""
        if (lifts_at := quota_lifts_at(response)) is None:
            return
        refused_until = datetime.fromtimestamp(lifts_at, tz=timezone.utc)
        # Requests already in flight answer in any order; the later lift is the one still in force.
        until = max(refused_until, _rate_limit_holds.get(self.instance_id, refused_until))
        _rate_limit_holds[self.instance_id] = until
        logger.warning(
            "GitHub rate-limited the token of instance '%s' until %s; no call goes out before then.",
            self.instance.name,
            f"{until:%Y-%m-%d %H:%M:%S UTC}",
        )

    async def list_branches(self, owner: str, repo: str) -> list[str] | None:
        return await self._branch_names(f"/repos/{owner}/{repo}/branches")

    async def get_default_branch(self, owner: str, repo: str) -> str | None:
        response = await self._get_ok(f"/repos/{owner}/{repo}")
        if response is None:
            return None
        branch = json_document(response).get("default_branch")
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
        """Wrapped so a None answer is cached for ttl_seconds rather than the generic negative-result TTL."""

        async def wrapped() -> dict[str, Any]:
            return {_CACHED_FIELD: await fetch()}

        cached = await cache_service.get_or_fetch_with_lock(
            self._get_cache_key(suffix), wrapped, ttl_seconds=ttl_seconds, max_wait_seconds=max_wait_seconds
        )
        value = cached.get(_CACHED_FIELD) if isinstance(cached, dict) else None
        return value if isinstance(value, expected_type) else None

    async def team_writes_to_repository(self, org: str, team_slug: str, team_id: int, repo: str) -> bool | None:
        """Works with a read-only org token; listing a repository's teams would need admin on every repository."""
        cache_key = self._get_cache_key(f"team_write:{org}/{team_id}:{org}/{repo}")
        cached: bool | None = await cache_service.get(cache_key)
        if cached is not None:
            return cached

        endpoint = f"/orgs/{org}/teams/{team_slug}/repos/{org}/{repo}"
        async with request_gate(self.instance_id):
            response = await self._api_get(endpoint, headers={"Accept": _REPOSITORY_ACCEPT})
        if response is None:
            return None

        if response.status_code == 200:
            # The endpoint answers 200 on pull as on admin, so the permission level in the body decides.
            writes = _team_writes_to(json_document(response))
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
            # A refusal read as "the team lacks the repository" would retire the team from every project it owns.
            logger.warning("GitHub API GET %s returned HTTP %d", endpoint, response.status_code)
            return None

        await cache_service.set(cache_key, writes, ttl_seconds=GITHUB_TEAM_SYNC_CACHE_TTL)
        return writes

    async def _repository_visible(self, org: str, repo: str) -> bool | None:
        async def fetch() -> bool | None:
            endpoint = f"/repos/{org}/{repo}"
            async with request_gate(self.instance_id):
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

    async def _is_personal_account(self, owner: str) -> bool:
        """A user's repositories, unlike an organisation's, no team can hold."""

        async def fetch() -> bool | None:
            async with request_gate(self.instance_id):
                response = await self._get_ok(f"/users/{owner}")
            return None if response is None else json_document(response).get("type") == "User"

        return await self._cached(f"owner_kind:{owner}", fetch, bool) is True

    async def get_org_teams(self, org: str) -> list[dict[str, Any]] | None:
        async def fetch() -> list[dict[str, Any]] | None:
            async with request_gate(self.instance_id):
                teams = await self._api_get_paginated(f"/orgs/{org}/teams")
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
        written: list[str] = []
        async with request_gate(self.instance_id):
            if budget.when() is None:
                budget.reschedule(asyncio.get_running_loop().time() + _GITHUB_ORG_WALK_TIMEOUT)
            async with aclosing(self._iter_pages(f"/orgs/{org}/teams/{slug}/repos")) as pages:
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
        """None unless every team answered within budget: an unreached team would read as holding nothing."""
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
        """One walk per org and TTL behind the stampede lock: a run's jobs arrive together and would each walk."""
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
        """Uncached: a connection test must see the token as it is now, not five minutes ago."""
        endpoint = f"/orgs/{org}/teams"
        async with request_gate(self.instance_id):
            response = await self._api_get(endpoint, params={"per_page": 1})
        if response is None or not self._ok(endpoint, response):
            return None
        # One team per page, so the last page's number is the count.
        last = urllib.parse.urlsplit(response.links.get("last", {}).get("url", ""))
        page = urllib.parse.parse_qs(last.query).get("page", [""])[0]
        if page.isdigit():
            return int(page)
        teams = response.json()
        return len(teams) if isinstance(teams, list) else None

    async def get_team_members(self, org: str, team_slug: str, team_id: int) -> list[dict[str, Any]] | None:
        """Cached on the numeric id because the slug is renameable."""

        async def fetch() -> list[dict[str, Any]] | None:
            endpoint = f"/orgs/{org}/teams/{team_slug}/members"
            members: list[dict[str, Any]] = []
            # The endpoint returns plain user objects, so the role can only come from the query.
            for github_role, role in _GITHUB_TEAM_ROLES:
                async with request_gate(self.instance_id):
                    page = await self._api_get_paginated(endpoint, params={"role": github_role})
                if page is None:
                    return None
                members.extend({"login": user["login"], "role": role} for user in page if user.get("login"))
            return members

        members: list[dict[str, Any]] | None = await self._cached(f"team_member_roles:{org}/{team_id}", fetch, list)
        return members

    async def get_viewer_organisations(self) -> list[dict[str, Any]] | None:
        """Uncached: a connection test must see the token as it is now, not five minutes ago."""
        return await self._api_get_paginated("/user/orgs")

    async def get_core_rate_limit(self) -> GitHubCoreRateLimit | None:
        """GET /rate_limit costs no quota; None also on GHES without rate limits."""
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

    async def _resolve_logins(self, logins: list[str], user_repo: UserRepository) -> dict[str, dict[str, Any]] | None:
        """Matched by verified public email, never by username."""
        emails = await self._public_emails(logins)
        if emails is None:
            return None
        by_email = await user_repo.verified_users_by_email({email for email in emails.values() if email})
        return {login: user for login, email in emails.items() if email and (user := by_email.get(email.lower()))}

    async def resolve_login(self, login: str, user_repo: UserRepository) -> dict[str, Any] | None:
        """Only an existing local user who verified the login's public email; never creates one."""
        return (await self._resolve_logins([login], user_repo) or {}).get(login)

    async def _build_team_members(
        self,
        members: list[dict[str, Any]],
        user_repo: UserRepository,
    ) -> list[TeamMember] | None:
        users = await self._resolve_logins([member["login"] for member in members], user_repo)
        if users is None:
            return None
        resolved: list[tuple[str, str]] = []
        for member in members:
            user = users.get(member["login"])
            if user is None:
                # Sync never creates users; a real member is added on their next sync after logging in via OIDC.
                logger.debug("Skipping GitHub member that resolved to no local user (login=%s).", member["login"])
                continue
            resolved.append((str(user["_id"]), member["role"]))
        return self._team_members(resolved)

    @staticmethod
    def _renamed_fields(team: dict[str, Any], binding: dict[str, Any], org: str, team_slug: str) -> dict[str, Any]:
        """Rename only a team still named by this binding; another binding's name would flip back and forth."""
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
        """None team_members leaves members alone without blocking the rename, since few logins resolve."""
        binding = binding_of(team, self.instance_id) or {}
        # The binding is the numeric team id, so a renamed slug or organisation has to follow it.
        binding_fields: dict[str, Any] = {}
        if binding.get("slug") != holder.slug:
            binding_fields["slug"] = holder.slug
        if str(binding.get("org") or "").casefold() != org.casefold():
            binding_fields["org"] = org
        await self._write_team_refresh(
            team_repo,
            team,
            holder.team_id,
            self._renamed_fields(team, binding, org, holder.slug),
            binding_fields,
            team_members,
        )

    async def _team_for_github_group(
        self,
        team_repo: TeamRepository,
        org: str,
        team_id: int,
        slug: str,
    ) -> dict[str, Any] | None:
        """Never matched by name, which any team admin can set; created even if no member resolves, as few logins do."""
        existing = await team_repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, self.instance_id, team_id)
        if existing:
            return existing

        team = Team(
            name=_auto_team_name(org, slug),
            description=_auto_team_description(org, slug),
            bindings=[GitHubTeamBinding(instance_id=self.instance_id, org=org, external_id=team_id, slug=slug)],
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
        """Current owners are added because the listing can omit them."""
        addressed = []
        for team in bound_teams:
            owns = str(team["_id"]) in current_owner_ids
            team_id = (binding_of(team, self.instance_id) or {}).get("external_id")
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
        """None on any unanswered check, which would otherwise retire its owner."""
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
        """Read every sync so a group granted access later is found."""
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
        """Reads only: nothing is written before the whole set is known."""
        org_teams = await self.get_org_teams(org)
        if org_teams is None:
            if await self._is_personal_account(org):
                return []
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
            # Members GitHub would not answer for are missing; writing the set would retire them from the team.
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
        """Never raises."""
        try:
            parts = split_repo_path(repository_path)
            if parts is None:
                logger.warning(
                    "GitHub repository claim %r names no owner/repo; leaving its owners untouched.", repository_path
                )
                return TeamSyncResult(None)
            org, repo = parts
            team_repo = TeamRepository(db)
            bound_teams = await team_repo.find_raw_by_github_org(self.instance_id, org)

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

            # Local writes stay outside the deadline: the ownership answer below needs every holder to have a team.
            teams: list[dict[str, Any]] = []
            for holder in holders:
                team = holder.team or await self._team_for_github_group(team_repo, org, holder.team_id, holder.slug)
                if team is None:
                    return TeamSyncResult(None)
                teams.append(team)
            user_repo = UserRepository(db)
            members: list[list[TeamMember] | None] = [None] * len(holders)
            try:
                # The same deadline, so all per-team reads share one budget instead of each getting a whole one.
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

    async def get_pull_requests_for_commit(
        self, owner: str, repo: str, commit_sha: str, branch: str
    ) -> tuple[str, list[GitHubPullRequest]]:
        pull_requests_for = partial(self._pull_requests_for_sha, owner, repo)
        if not branch.endswith("/merge"):
            return commit_sha, await pull_requests_for(commit_sha)
        # A "<number>/merge" build runs a test-merge commit GitHub links to no PR (200, []).
        return await self._requests_for_merge_build(
            f"{owner}/{repo}",
            commit_sha,
            pull_requests_for,
            partial(self._commit_parents, owner, repo),
            lambda pr: branch == f"{pr.number}/merge",
        )

    async def _pull_requests_for_sha(self, owner: str, repo: str, sha: str) -> list[GitHubPullRequest]:
        response = await self._get_ok(f"/repos/{owner}/{repo}/commits/{sha}/pulls")
        return [] if response is None else [GitHubPullRequest(**pr) for pr in response.json()]

    async def _commit_parents(self, owner: str, repo: str, commit_sha: str) -> list[str]:
        # The git object, not the REST commit, which also carries every changed file and its patch.
        response = await self._get_ok(f"/repos/{owner}/{repo}/git/commits/{commit_sha}")
        parents = [] if response is None else json_document(response).get("parents") or []
        return [str(parent.get("sha") or "") for parent in parents]

    async def find_pull_request_comments(
        self, owner: str, repo: str, pr_number: int, matches: Callable[[GitHubIssueComment], bool]
    ) -> list[GitHubIssueComment] | None:
        # GitHub lists issue comments oldest first.
        return await self._first_page_matches(
            f"/repos/{owner}/{repo}/issues/{pr_number}/comments", GitHubIssueComment, matches
        )

    async def post_pull_request_comment(self, owner: str, repo: str, pr_number: int, body: str) -> bool:
        return await self._send_comment("POST", f"/repos/{owner}/{repo}/issues/{pr_number}/comments", body)

    async def update_pull_request_comment(self, owner: str, repo: str, comment_id: int, body: str) -> bool:
        return await self._send_comment("PATCH", f"/repos/{owner}/{repo}/issues/comments/{comment_id}", body)

    async def _jwks_uris(self) -> list[str]:
        if _hostname(self.base_url) == _hostname(GITHUB_SHARED_OIDC_ISSUER):
            return [_GITHUB_COM_JWKS_URI]
        discovered = await discover_jwks_uri(self.base_url, self._get_cache_key(f"jwks_uri:{self.base_url}"))
        return [discovered or f"{self.base_url}/.well-known/jwks"]
