import logging
import urllib.parse
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx

from app.core.cache import cache_service
from app.core.constants import (
    GITHUB_JWKS_CACHE_TTL,
    GITHUB_JWKS_URI_CACHE_TTL,
    GITHUB_TEAM_SYNC_CACHE_TTL,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
)
from app.core.http_utils import InstrumentedAsyncClient
from app.models.github_api import GitHubIssueComment, GitHubOIDCPayload, GitHubPullRequest
from app.models.github_instance import GitHubInstance
from app.models.team import TeamMember
from app.repositories import UserRepository
from app.services.oidc_utils import validate_oidc_token as _validate_oidc_token

logger = logging.getLogger(__name__)

_GITHUB_COM_JWKS_URI = "https://token.actions.githubusercontent.com/.well-known/jwks"


_GITHUB_API_TIMEOUT = 10.0

# Direct access outranks an omitted access_source, which outranks the inherited "organization"/
# "enterprise". A value we cannot interpret ranks as inherited too: absence is missing information,
# while a future enum member ranked above an explicit weaker source would silently reassign teams.
_ACCESS_SOURCE_INHERITED = 0
_ACCESS_SOURCE_ABSENT = 1
_ACCESS_SOURCE_DIRECT = 2

_PERMISSION_RANK = {"pull": 0, "triage": 1, "push": 2, "maintain": 3, "admin": 4}


def _team_id(team: dict[str, Any]) -> int | None:
    """None for an id we cannot order by; such a team is skipped, never fatal to the whole repository."""
    try:
        return int(team["id"])
    except (KeyError, TypeError, ValueError):
        return None


def build_team_depth_map(org_teams: list[dict[str, Any]]) -> dict[int, int]:
    """Team id -> nesting depth from GET /orgs/{org}/teams; the repository call carries one level only."""
    parents: dict[int, int | None] = {}
    for team in org_teams:
        team_id = _team_id(team)
        if team_id is None:
            continue
        parents[team_id] = _team_id(team.get("parent") or {})

    depths: dict[int, int] = {}
    for team_id, parent_id in parents.items():
        depth = 0
        seen = {team_id}
        current = parent_id
        # A parent outside the map is a team this token cannot see; `seen` stops a cycle from hanging the sync.
        while current is not None and current in parents and current not in seen:
            seen.add(current)
            depth += 1
            current = parents[current]
        depths[team_id] = depth
    return depths


def _access_source_rank(team: dict[str, Any]) -> int:
    access_source = team.get("access_source")
    if access_source is None:
        return _ACCESS_SOURCE_ABSENT
    return _ACCESS_SOURCE_DIRECT if str(access_source) == "direct" else _ACCESS_SOURCE_INHERITED


def _permission_rank(team: dict[str, Any]) -> int:
    permissions = team.get("permissions")
    # The legacy `permission` string collapses maintain onto push and triage onto pull.
    if isinstance(permissions, dict):
        return max((rank for name, rank in _PERMISSION_RANK.items() if permissions.get(name)), default=-1)
    return _PERMISSION_RANK.get(str(team.get("permission") or ""), -1)


def _sort_key(team_id: int, team: dict[str, Any], depth_map: dict[int, int] | None) -> tuple[int, int, int, int]:
    depth = depth_map.get(team_id, 0) if depth_map else 0
    return (-_access_source_rank(team), -depth, -_permission_rank(team), team_id)


def select_github_team(
    candidates: list[dict[str, Any]],
    depth_map: dict[int, int] | None = None,
) -> dict[str, Any] | None:
    """Direct access, then depth, then permission, then the lowest id.

    The id keeps the order total: without it two equally-ranked teams swap between syncs and the
    project's team assignment flips with nothing in the logs to explain it.
    """
    ranked = [(team_id, team) for team in candidates if (team_id := _team_id(team)) is not None]
    if not ranked:
        return None
    return min(ranked, key=lambda entry: _sort_key(entry[0], entry[1], depth_map))[1]


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

    def _get_auth_headers(self) -> dict[str, str]:
        if not self.instance.access_token:
            raise ValueError(f"No access token configured for GitHub instance '{self.instance.name}'")
        return {"Authorization": f"Bearer {self.instance.access_token}", "Accept": "application/vnd.github+json"}

    @asynccontextmanager
    async def _api_client(self) -> AsyncIterator[InstrumentedAsyncClient]:
        async with InstrumentedAsyncClient("GitHub API", timeout=_GITHUB_API_TIMEOUT) as client:
            yield client

    async def _api_get(self, endpoint: str, params: dict[str, Any] | None = None) -> httpx.Response | None:
        if not self.instance.access_token:
            return None

        try:
            async with self._api_client() as client:
                return await client.get(
                    f"{self.api_url}{endpoint}",
                    headers=self._get_auth_headers(),
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

    async def get_repository_teams(self, owner: str, repo: str) -> list[dict[str, Any]] | None:
        """Teams with access to a repository. Returns None on API failure."""
        return await self._get_cached_all_pages(
            self._get_cache_key(f"repo_teams:{owner}/{repo}"),
            f"/repos/{owner}/{repo}/teams",
        )

    async def get_org_teams(self, org: str) -> list[dict[str, Any]] | None:
        """Every team of an organisation with its parent, for the nesting-depth map."""
        return await self._get_cached_all_pages(self._get_cache_key(f"org_teams:{org}"), f"/orgs/{org}/teams")

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
        """The public profile email, or None when the user hides it."""
        response = await self._api_get(f"/users/{login}")
        if response is not None and response.status_code == 200:
            email = response.json().get("email")
            return str(email) if email else None
        # A refusal read as "no public email" would silently disable email matching for every member.
        if response is not None and response.status_code != 404:
            logger.warning("GitHub API GET /users/%s failed: %s", login, response.status_code)
        return None

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
    ) -> list[TeamMember]:
        """Map GitHub members onto existing local users, tagged source="github" for the merge."""
        team_members: list[TeamMember] = []
        for member in members:
            login = member["login"]
            user = await self._find_user_for_github_member(login, user_repo)
            if not user:
                # Sync never creates users; a real member is added on their next sync after
                # logging in via OIDC.
                logger.debug("Skipping GitHub member with no local account (login=%s).", login)
                continue
            role = TEAM_ROLE_ADMIN if member.get("role") == "maintainer" else TEAM_ROLE_MEMBER
            user_id = str(user.get("_id", user.get("id")))
            team_members.append(TeamMember(user_id=user_id, role=role, source="github"))
        unresolved = len(members) - len(team_members)
        if unresolved:
            # The per-member misses are DEBUG, so this is the only signal at INFO that a token
            # without profile access has broken matching wholesale.
            logger.info(
                "GitHub team sync resolved %d of %d members; %d have no local account.",
                len(team_members),
                len(members),
                unresolved,
            )
        return team_members

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
