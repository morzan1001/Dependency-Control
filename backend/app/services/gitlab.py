import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, NamedTuple

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.cache import cache_service
from app.core.constants import (
    GITLAB_ADMIN_MIN_ACCESS,
    GITLAB_JWKS_CACHE_TTL,
    GITLAB_JWKS_URI_CACHE_TTL,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
    TEAM_SOURCE_GITLAB,
    team_source,
)
from app.core.http_utils import InstrumentedAsyncClient
from app.models.gitlab_api import (
    GitLabMember,
    GitLabMergeRequest,
    GitLabNote,
    GitLabProjectDetails,
    OIDCPayload,
)
from app.models.gitlab_instance import GitLabInstance
from app.models.team import GitLabGroupBinding, Team, TeamMember, binding_of
from app.repositories import TeamRepository, UserRepository
from app.repositories.teams import MemberSubset
from app.services.oidc_utils import validate_oidc_token as _validate_oidc_token

logger = logging.getLogger(__name__)

_GITLAB_API_TIMEOUT = 10.0

# The group lookup and the member listing run inside the ingest request, and the listing is
# uncapped, so a large group is many pages of 10s each. This bounds the reads as a whole.
_GITLAB_RESOLUTION_TIMEOUT = 30.0

_AUTO_TEAM_NAME_PREFIX = "GitLab Group:"


def _auto_team_name(group_path: str) -> str:
    """The name a team gets while nobody has renamed it; the prefix is what marks it as ours to set."""
    return f"{_AUTO_TEAM_NAME_PREFIX} {group_path}"


def _auto_team_description(group_path: str) -> str:
    return f"Imported from GitLab Group {group_path}"


class GitLabGroupLookup(NamedTuple):
    """One group read back from an instance.

    ``reachable`` separates "this instance carries no such group" from "the instance did not
    answer": the first is the caller's mistake, the second is not.
    """

    reachable: bool
    group: dict[str, Any] | None


def build_group_options(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The groups a human can bind to, with the full path that tells two same-named subgroups
    apart. An entry that cannot address a group is left out, as it is everywhere else."""
    options = []
    for group in groups:
        group_id = group.get("id")
        full_path = group.get("full_path") or group.get("path")
        if not isinstance(group_id, int) or not full_path:
            continue
        options.append(
            {
                "id": group_id,
                "full_path": str(full_path),
                "name": str(group.get("name") or full_path),
            }
        )
    return options


class GitLabTeamSyncResult(NamedTuple):
    """The Dependency Control teams GitLab says own the project — at most the one group's.

    ``team_ids`` is None when GitLab could not be asked, which is not the empty list: the first
    leaves the project's GitLab owner alone, the second retires it.
    """

    team_ids: list[str] | None


class GitLabSyncTarget(NamedTuple):
    """The GitLab group that should back the team for one project.

    ``determined`` is False for a question GitLab did not answer. ``group`` is None while
    ``determined`` holds for a project no group owns at all, which retires the group owner it had.
    """

    group: tuple[int, str] | None
    determined: bool = True


_UNDETERMINED_TARGET = GitLabSyncTarget(None, determined=False)
_NO_OWNING_GROUP = GitLabSyncTarget(None)


class GitLabService:
    def __init__(self, gitlab_instance: GitLabInstance):
        self.instance = gitlab_instance
        self.base_url = gitlab_instance.url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v4"
        self._cache_key_prefix = f"instance:{gitlab_instance.id}"

    def _get_cache_key(self, suffix: str) -> str:
        """Generate cache key for this specific instance."""
        return f"gitlab:{self._cache_key_prefix}:{suffix}"

    def _get_auth_headers(self) -> dict[str, str]:
        if not self.instance.access_token:
            raise ValueError(f"No access token configured for GitLab instance '{self.instance.name}'")
        return {"PRIVATE-TOKEN": self.instance.access_token}

    @asynccontextmanager
    async def _api_client(self) -> AsyncIterator[InstrumentedAsyncClient]:
        async with InstrumentedAsyncClient("GitLab API", timeout=_GITLAB_API_TIMEOUT) as client:
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
            logger.exception("GitLab API GET %s failed: %s: %s", endpoint, type(e).__name__, e)
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
            logger.exception("GitLab API POST %s failed: %s: %s", endpoint, type(e).__name__, e)
            return None

    async def _api_put(self, endpoint: str, json_data: dict[str, Any] | None = None) -> httpx.Response | None:
        if not self.instance.access_token:
            return None

        try:
            async with self._api_client() as client:
                return await client.put(
                    f"{self.api_url}{endpoint}",
                    headers=self._get_auth_headers(),
                    json=json_data,
                )
        except Exception as e:
            logger.exception("GitLab API PUT %s failed: %s: %s", endpoint, type(e).__name__, e)
            return None

    async def _api_get_paginated(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        max_pages: int | None = 10,
    ) -> list[dict[str, Any]] | None:
        """Paginated GET; returns all items or None on failure.

        ``max_pages=None`` fetches all pages uncapped; a hit finite cap logs a
        truncation WARNING.
        """
        if not self.instance.access_token:
            return None

        all_items: list[dict[str, Any]] = []
        page = 1
        per_page = 100  # GitLab max per_page

        try:
            async with self._api_client() as client:
                while max_pages is None or page <= max_pages:
                    response = await client.get(
                        f"{self.api_url}{endpoint}",
                        headers=self._get_auth_headers(),
                        params={**(params or {}), "page": page, "per_page": per_page},
                    )
                    if response.status_code != 200:
                        logger.error(f"GitLab API GET {endpoint} page {page} failed: {response.status_code}")
                        return None

                    items = response.json()
                    if not items:
                        break
                    all_items.extend(items)

                    if self._is_last_page(items, per_page, page, response.headers.get("x-total-pages")):
                        break
                    if self._cap_reached(endpoint, page, max_pages, per_page, response.headers.get("x-total-pages")):
                        break
                    page += 1

        except Exception as e:
            logger.exception("GitLab API paginated GET %s failed: %s: %s", endpoint, type(e).__name__, e)
            return None

        return all_items

    @staticmethod
    def _is_last_page(items: list[Any], per_page: int, page: int, total_pages: str | None) -> bool:
        """True when GitLab signals there are no further pages to fetch."""
        if total_pages and page >= int(total_pages):
            return True
        return len(items) < per_page

    @staticmethod
    def _cap_reached(endpoint: str, page: int, max_pages: int | None, per_page: int, total_pages: str | None) -> bool:
        """True (and logs a WARNING) when a finite cap is hit while more pages remain."""
        if max_pages is None or page < max_pages:
            return False
        logger.warning(
            "GitLab API GET %s hit the pagination cap of %d page(s) (~%d items) but GitLab "
            "reports more remain (x-total-pages=%s). Result is TRUNCATED.",
            endpoint,
            max_pages,
            max_pages * per_page,
            total_pages or "unknown",
        )
        return True

    async def _get_jwks_uri(self) -> str | None:
        """Resolve the JWKS URI from the OIDC discovery document, Redis-cached."""
        cache_key = self._get_cache_key("jwks_uri")

        cached_uri = await cache_service.get(cache_key)
        if cached_uri:
            result: str = cached_uri
            return result

        async with InstrumentedAsyncClient("GitLab OIDC", timeout=10.0) as client:
            try:
                response = await client.get(f"{self.base_url}/.well-known/openid-configuration")
                if response.status_code == 200:
                    config = response.json()
                    jwks_uri: str | None = config.get("jwks_uri")
                    if jwks_uri:
                        await cache_service.set(cache_key, jwks_uri, ttl_seconds=GITLAB_JWKS_URI_CACHE_TTL)
                    return jwks_uri
            except Exception as e:
                logger.warning(f"Error fetching OIDC discovery: {type(e).__name__}: {e}")

        return None

    async def _fetch_jwks_from_uri(
        self,
        client: InstrumentedAsyncClient,
        jwks_uri: str,
        cache_key: str,
    ) -> dict | None:
        """Fetch JWKS from a known URI and cache it; returns None if unavailable."""
        response = await client.get(jwks_uri)
        if response.status_code != 200:
            return None
        jwks: dict[Any, Any] = response.json()
        await cache_service.set(cache_key, jwks, ttl_seconds=GITLAB_JWKS_CACHE_TTL)
        return jwks

    async def _fetch_jwks_from_fallbacks(
        self,
        client: InstrumentedAsyncClient,
        cache_key: str,
    ) -> dict | None:
        """Try common fallback JWKS endpoints; returns None if all fail."""
        for path in ["/oauth/discovery/keys", "/-/jwks"]:
            response = await client.get(f"{self.base_url}{path}")
            if response.status_code == 200:
                jwks_fallback: dict[Any, Any] = response.json()
                await cache_service.set(cache_key, jwks_fallback, ttl_seconds=GITLAB_JWKS_CACHE_TTL)
                logger.info(f"JWKS fetched from fallback path: {path}")
                return jwks_fallback
        return None

    async def _try_fetch_jwks_once(self, cache_key: str) -> dict | None:
        """Single attempt to fetch JWKS via discovery + fallbacks. Returns {} on definitive failure."""
        async with InstrumentedAsyncClient("GitLab JWKS", timeout=10.0) as client:
            jwks_uri = await self._get_jwks_uri()
            if jwks_uri:
                jwks = await self._fetch_jwks_from_uri(client, jwks_uri, cache_key)
                if jwks is not None:
                    return jwks

            fallback = await self._fetch_jwks_from_fallbacks(client, cache_key)
            if fallback is not None:
                return fallback

            logger.error(f"Failed to fetch JWKS from any known endpoint for {self.base_url}")
            return {}

    async def get_jwks(self) -> dict | None:
        """Fetch and Redis-cache the JWKS from GitLab, retrying on transient failure."""
        cache_key = self._get_cache_key("jwks")

        cached_jwks = await cache_service.get(cache_key)
        if cached_jwks:
            result_jwks: dict[Any, Any] = cached_jwks
            return result_jwks

        import asyncio as _asyncio

        for attempt in range(3):
            try:
                return await self._try_fetch_jwks_once(cache_key)
            except Exception as e:
                logger.warning(
                    f"JWKS fetch attempt {attempt + 1}/3 failed for {self.base_url}: {type(e).__name__}: {e}"
                )
                if attempt < 2:
                    await _asyncio.sleep(1)
        logger.error(f"JWKS fetch failed after 3 attempts for {self.base_url}")
        return {}

    async def _invalidate_jwks_cache(self) -> None:
        """Invalidate the JWKS cache to force a refresh on next request."""
        cache_key = self._get_cache_key("jwks")
        await cache_service.delete(cache_key)

    async def validate_oidc_token(self, token: str) -> OIDCPayload | None:
        """Validate a GitLab OIDC JWT, refreshing JWKS on key rotation."""
        return await _validate_oidc_token(
            token=token,
            get_jwks=self.get_jwks,
            invalidate_cache=self._invalidate_jwks_cache,
            issuer=self.base_url,
            # `or None` normalizes "" -> None so unconfigured instances fail the audience check closed.
            audience=self.instance.oidc_audience or None,
            payload_model=OIDCPayload,
            provider_name="GitLab",
        )

    async def list_branches(self, project_id: int) -> list[str] | None:
        """Fetches all branch names from a GitLab project. Returns None on API failure."""
        branches = await self._api_get_paginated(f"/projects/{project_id}/repository/branches")
        if branches is None:
            return None
        return [b["name"] for b in branches]

    async def get_project_details(self, project_id: int) -> GitLabProjectDetails | None:
        """Fetches project details using the system token."""
        response = await self._api_get(f"/projects/{project_id}")
        if response and response.status_code == 200:
            return GitLabProjectDetails(**response.json())
        return None

    async def get_merge_requests_for_commit(self, project_id: int, commit_sha: str) -> list[GitLabMergeRequest]:
        """Fetches merge requests associated with a specific commit."""
        response = await self._api_get(f"/projects/{project_id}/repository/commits/{commit_sha}/merge_requests")
        if response and response.status_code == 200:
            return [GitLabMergeRequest(**mr) for mr in response.json()]
        return []

    async def post_merge_request_comment(self, project_id: int, mr_iid: int, body: str) -> bool:
        """Posts a comment to a merge request."""
        response = await self._api_post(
            f"/projects/{project_id}/merge_requests/{mr_iid}/notes",
            json_data={"body": body},
        )
        if response:
            if response.status_code == 201:
                return True
            logger.error(f"Failed to post MR comment: {response.status_code} - {response.text}")
        return False

    async def get_merge_request_notes(self, project_id: int, mr_iid: int) -> list[GitLabNote]:
        """Fetch all notes (comments) from a merge request."""
        notes = await self._api_get_paginated(f"/projects/{project_id}/merge_requests/{mr_iid}/notes")
        return [GitLabNote(**n) for n in notes] if notes else []

    async def update_merge_request_comment(self, project_id: int, mr_iid: int, note_id: int, body: str) -> bool:
        """Updates an existing comment on a merge request."""
        response = await self._api_put(
            f"/projects/{project_id}/merge_requests/{mr_iid}/notes/{note_id}",
            json_data={"body": body},
        )
        if response:
            if response.status_code == 200:
                return True
            logger.error(f"Failed to update MR comment: {response.status_code} - {response.text}")
        return False

    async def get_project_members(self, project_id: int) -> list[GitLabMember] | None:
        """Fetch all project members (including group-inherited) via the system token."""
        if not self.instance.access_token:
            logger.warning("Cannot fetch project members: No system GitLab Access Token configured.")
            return None

        # /members/all includes inherited members; uncapped so large projects aren't truncated.
        members = await self._api_get_paginated(f"/projects/{project_id}/members/all", max_pages=None)
        # An empty list is a project nobody is left in, and stays a list; only None is a failure.
        return None if members is None else [GitLabMember(**m) for m in members]

    async def get_group_members(self, group_id: int) -> list[GitLabMember] | None:
        """Fetch all group members via the system token."""
        if not self.instance.access_token:
            logger.warning("Cannot fetch group members: No system GitLab Access Token configured.")
            return None

        # Uncapped so large groups aren't silently truncated.
        members = await self._api_get_paginated(f"/groups/{group_id}/members/all", max_pages=None)
        # An empty list is a group nobody is left in, and stays a list; only None is a failure.
        return None if members is None else [GitLabMember(**m) for m in members]

    async def get_groups(self, search: str | None = None) -> list[dict[str, Any]] | None:
        """The groups this instance's token can see, to pick from when binding a team.

        GitLab scopes /groups to the token's own memberships, or to everything for an
        administrator; ``search`` is what reaches a group beyond the pagination cap.
        """
        params: dict[str, Any] = {"order_by": "path", "sort": "asc"}
        if search:
            params["search"] = search
        return await self._api_get_paginated("/groups", params=params)

    async def get_group(self, group_id: int) -> GitLabGroupLookup:
        """One group by its numeric id."""
        response = await self._api_get(f"/groups/{group_id}")
        if response is None:
            return GitLabGroupLookup(reachable=False, group=None)
        if response.status_code == 200:
            group: dict[str, Any] = response.json()
            return GitLabGroupLookup(reachable=True, group=group)
        # 404 is also what GitLab answers for a group the token may not see, which is the same
        # answer for a binding: this instance cannot resolve it.
        if response.status_code == 404:
            return GitLabGroupLookup(reachable=True, group=None)
        logger.error("GitLab GET /groups/%s answered %s", group_id, response.status_code)
        return GitLabGroupLookup(reachable=False, group=None)

    async def _resolve_group_by_path(self, group_path: str) -> GitLabGroupLookup:
        """One group by its full path."""
        import urllib.parse

        encoded_path = urllib.parse.quote(group_path, safe="")
        response = await self._api_get(f"/groups/{encoded_path}")
        if response is None:
            return GitLabGroupLookup(reachable=False, group=None)
        if response.status_code == 200:
            group: dict[str, Any] = response.json()
            return GitLabGroupLookup(reachable=True, group=group)
        # 404 is also what GitLab answers for a group the token may not see, which is the same
        # answer here: this instance cannot resolve it.
        if response.status_code == 404:
            return GitLabGroupLookup(reachable=True, group=None)
        logger.error("GitLab GET /groups/%s answered %s", group_path, response.status_code)
        return GitLabGroupLookup(reachable=False, group=None)

    async def _resolve_sync_target_group(
        self,
        gitlab_project_id: int,
        gitlab_project_path: str,
        gitlab_project_data: GitLabProjectDetails | None,
    ) -> GitLabSyncTarget:
        """Which GitLab group (id, path) should back the team for this project."""
        if not gitlab_project_data or not gitlab_project_data.namespace:
            logger.warning(
                f"Skipping team sync for project_id={gitlab_project_id} ({gitlab_project_path}): "
                f"no GitLab project details available (likely access denied or 404 on /projects/{gitlab_project_id})."
            )
            return _UNDETERMINED_TARGET

        if gitlab_project_data.namespace.kind != "group":
            # Determined, not unknown: GitLab answered, and its answer is that a person owns this
            # project. A group owner it carries from before the move is retired on the strength of it.
            logger.info(
                f"No GitLab group owns project_id={gitlab_project_id} ({gitlab_project_path}): "
                f"namespace is a user namespace, so any group owner it still carries is retired."
            )
            return _NO_OWNING_GROUP

        namespace = gitlab_project_data.namespace
        group_id = namespace.id
        group_path = namespace.full_path

        # team_sync_depth sets team granularity: depth=1 "mo/edge/k8s" -> "mo",
        # depth=2 -> "mo/edge", depth=0 -> full path.
        depth = getattr(self.instance, "team_sync_depth", 1)
        if depth <= 0:
            return GitLabSyncTarget((group_id, group_path))

        parts = group_path.split("/")
        truncated_path = "/".join(parts[:depth])
        if len(parts) <= depth:
            return GitLabSyncTarget((group_id, truncated_path))

        parent = await self._resolve_group_by_path(truncated_path)
        if parent.group:
            return GitLabSyncTarget((parent.group["id"], truncated_path))

        # An ancestor of a group this instance carries exists by construction, so a 404 here is a
        # group the token may not see rather than one that is gone. Either way, falling back to the
        # deepest namespace would bind a team of different granularity than every other run of this
        # instance, splitting one group's people across two teams.
        logger.warning(
            "Could not resolve GitLab group path '%s' (reachable=%s) while syncing project_id=%s; "
            "the owner stays undetermined rather than being bound at the deepest namespace '%s'.",
            truncated_path,
            parent.reachable,
            gitlab_project_id,
            group_path,
        )
        return _UNDETERMINED_TARGET

    @property
    def _member_source(self) -> str:
        """The provenance of a member this instance resolves, and the subset its sync replaces."""
        return team_source(TEAM_SOURCE_GITLAB, str(self.instance.id))

    async def _build_team_members(
        self,
        gitlab_members: list[GitLabMember],
        user_repo: UserRepository,
    ) -> tuple[list[TeamMember], int]:
        """Resolve each GitLab member to an EXISTING local user, plus the unresolved count.

        Tagged with this instance so the merge in ``_upsert_team_with_members`` refreshes only the
        subset this instance established. Members without a local account are skipped — sync never
        creates users (see ``_find_user``).
        """
        resolved: dict[str, TeamMember] = {}
        unresolved = 0
        for member in gitlab_members:
            user = await self._find_user(member, user_repo)
            if not user:
                # No local account yet, or a GitLab service account/bot. Sync never creates
                # users; a real member is added on their next sync after logging in via OIDC.
                unresolved += 1
                logger.debug(
                    "Skipping GitLab member with no local account (username=%s, access_level=%s).",
                    member.username,
                    member.access_level,
                )
                continue
            role = TEAM_ROLE_ADMIN if member.access_level >= GITLAB_ADMIN_MIN_ACCESS else TEAM_ROLE_MEMBER
            user_id = str(user.get("_id", user.get("id")))
            # Two GitLab members can resolve to one local user. A duplicate entry breaks
            # add_member's $ne guard, and a last-wins merge would silently demote the admin entry.
            previous = resolved.get(user_id)
            if previous is not None and previous.role == TEAM_ROLE_ADMIN:
                continue
            resolved[user_id] = TeamMember(user_id=user_id, role=role, source=self._member_source)
        return list(resolved.values()), unresolved

    async def _find_user(
        self,
        member: GitLabMember,
        user_repo: UserRepository,
    ) -> dict[str, Any] | None:
        """Resolve a GitLab member to an EXISTING local user: the public email, then the username.

        The email comes with the listing and costs no request, so it is tried first; the username
        still has to be tried, or a member whose GitLab email differs from the one their account
        was created with is dropped although their handle names them exactly.

        Returns None when the member has no local account; sync never creates users.
        """
        if member.email:
            # Case-insensitive: OIDC-login email may differ in case, and an exact match
            # would silently drop a real member.
            user = await user_repo.get_raw_by_email_ci(member.email)
            if user:
                return user
        if member.username:
            return await user_repo.get_raw_by_username(member.username)
        return None

    async def _resolve_group_members(
        self,
        members: list[GitLabMember],
        user_repo: UserRepository,
        team_name: str,
        group_id: int,
    ) -> list[TeamMember] | None:
        """The members to store for a group, or None to leave the stored ones alone."""
        team_members, unresolved = await self._build_team_members(members, user_repo)
        if unresolved and not team_members:
            # A token that lost profile access resolves nobody; writing that would strip the
            # whole gitlab subset and read as a group everyone left.
            logger.warning(
                "Resolved 0 of %d members of GitLab group '%s' (group_id=%d); leaving the existing members untouched.",
                unresolved,
                team_name,
                group_id,
            )
            return None
        return team_members

    @staticmethod
    def _renamed_fields(team: dict[str, Any], group_path: str) -> dict[str, Any]:
        """The name to follow GitLab with, while the team still carries the generated one.

        A team its owner renamed keeps that name for good: only the prefix marks a name as ours.
        """
        current = str(team.get("name") or "")
        generated = _auto_team_name(group_path)
        if not current.startswith(_AUTO_TEAM_NAME_PREFIX) or current == generated:
            return {}
        return {"name": generated, "description": _auto_team_description(group_path)}

    async def _refresh_team(
        self,
        team_repo: TeamRepository,
        team: dict[str, Any],
        binding: GitLabGroupBinding,
        group_path: str,
        team_members: list[TeamMember] | None,
    ) -> None:
        """Write what GitLab has since changed about a bound team, and nothing when nothing has.

        ``team_members`` is None to leave the stored members alone, which the rename must not hang
        on: a group whose members none resolve would otherwise never follow a rename.
        """
        updates: dict[str, Any] = self._renamed_fields(team, group_path)
        # Handed to the server as the subset to replace rather than merged here: the snapshot is
        # several round trips old, and a member added in between would be written back out of the
        # team after the add had already reported success.
        subset = (
            MemberSubset(self._member_source, [member.model_dump() for member in team_members])
            if team_members is not None
            else None
        )
        stored = binding_of(team, binding.instance_id) or {}
        # A group that was renamed or moved has to carry the path GitLab reports now, including on
        # a team bound by hand before any sync ran.
        binding_fields = {"path": group_path} if stored.get("path") != group_path else {}
        if not updates and not binding_fields and subset is None:
            return
        await team_repo.update_with_binding(
            team["_id"],
            {**updates, "updated_at": datetime.now(timezone.utc)},
            binding.key,
            binding_fields,
            subset,
        )

    async def _upsert_team_with_members(
        self,
        team_repo: TeamRepository,
        existing_team: dict[str, Any] | None,
        instance_id: str,
        group_id: int,
        group_path: str,
        team_members: list[TeamMember] | None,
    ) -> str | None:
        """The team backing the group, refreshed or created; None when there is nothing to create."""
        binding = GitLabGroupBinding(instance_id=instance_id, external_id=group_id, path=group_path)
        if existing_team:
            await self._refresh_team(team_repo, existing_team, binding, group_path, team_members)
            return str(existing_team["_id"])
        if team_members:
            new_team = Team(
                name=_auto_team_name(group_path),
                description=_auto_team_description(group_path),
                bindings=[binding],
                members=team_members,
            )
            await team_repo.create(new_team)
            return str(new_team.id)
        return None

    async def _read_owning_group(
        self,
        gitlab_project_id: int,
        gitlab_project_path: str,
        gitlab_project_data: GitLabProjectDetails | None,
    ) -> tuple[GitLabSyncTarget, list[GitLabMember] | None]:
        """Everything this sync asks GitLab for: the owning group, and the members it holds."""
        target = await self._resolve_sync_target_group(gitlab_project_id, gitlab_project_path, gitlab_project_data)
        if target.group is None:
            return target, None
        return target, await self.get_group_members(target.group[0])

    async def sync_team_from_gitlab(
        self,
        db: AsyncIOMotorDatabase,
        gitlab_project_id: int,
        gitlab_project_path: str,
        gitlab_project_data: GitLabProjectDetails | None = None,
    ) -> GitLabTeamSyncResult:
        """Sync the GitLab group's members to a local Team and report which team owns the project.

        Undetermined on any failure: the owning group is what GitLab was asked for, and an
        unanswered question must not read as "this project has no GitLab owner".

        Never raises.
        """
        team_repo = TeamRepository(db)
        user_repo = UserRepository(db)

        try:
            try:
                # Only the reads are bounded: cancelling them costs nothing, while cancelling the
                # write would leave the team half-refreshed for no gain.
                async with asyncio.timeout(_GITLAB_RESOLUTION_TIMEOUT):
                    target, members = await self._read_owning_group(
                        gitlab_project_id, gitlab_project_path, gitlab_project_data
                    )
            except TimeoutError:
                logger.warning(
                    "Resolving the owning group of project_id=%s (%s) took longer than %.0fs; "
                    "leaving its owner untouched.",
                    gitlab_project_id,
                    gitlab_project_path,
                    _GITLAB_RESOLUTION_TIMEOUT,
                )
                return GitLabTeamSyncResult(None)

            if not target.determined:
                return GitLabTeamSyncResult(None)
            if target.group is None:
                return GitLabTeamSyncResult([])

            group_id, group_path = target.group
            team_name = _auto_team_name(group_path)
            instance_id = str(self.instance.id)

            if members is None:
                logger.warning(
                    f"Failed to fetch members for group '{team_name}' (group_id={group_id}) "
                    f"while syncing project_id={gitlab_project_id}. Skipping member sync."
                )
                # Match ONLY by the (instance, group) composite key. A name-based fallback
                # is unsafe: two instances owning a same-path group would collide cross-tenant.
                team = await team_repo.get_raw_by_binding(TEAM_SOURCE_GITLAB, instance_id, group_id)
                if team:
                    return GitLabTeamSyncResult([str(team["_id"])])
                logger.warning(
                    f"No existing team for group '{team_name}' (group_id={group_id}); "
                    f"the owner of project_id={gitlab_project_id} stays undetermined."
                )
                return GitLabTeamSyncResult(None)

            # Match ONLY by the (instance, group) composite key (see the failed-fetch branch above).
            existing_team = await team_repo.get_raw_by_binding(TEAM_SOURCE_GITLAB, instance_id, group_id)
            team_members = await self._resolve_group_members(members, user_repo, team_name, group_id)
            team_id = await self._upsert_team_with_members(
                team_repo, existing_team, instance_id, group_id, group_path, team_members
            )
            # No team and none creatable is an answer, not a failure: the group's members are all
            # strangers here, so nothing in Dependency Control owns the project.
            return GitLabTeamSyncResult([team_id] if team_id else [])

        except Exception as e:
            logger.exception(
                "Error syncing GitLab teams for project_id=%s (%s): %s: %s",
                gitlab_project_id,
                gitlab_project_path,
                type(e).__name__,
                e,
            )
            return GitLabTeamSyncResult(None)
