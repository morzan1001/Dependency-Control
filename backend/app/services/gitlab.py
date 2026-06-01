import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx

from app.core.http_utils import InstrumentedAsyncClient
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import security
from app.core.cache import cache_service
from app.core.constants import (
    GITLAB_ADMIN_MIN_ACCESS,
    GITLAB_JWKS_CACHE_TTL,
    GITLAB_JWKS_URI_CACHE_TTL,
)
from app.models.gitlab_api import (
    GitLabMember,
    GitLabMergeRequest,
    GitLabNote,
    GitLabProjectDetails,
    OIDCPayload,
)
from app.models.gitlab_instance import GitLabInstance
from app.models.team import Team, TeamMember
from app.models.user import User
from app.services.oidc_utils import validate_oidc_token as _validate_oidc_token
from app.repositories import TeamRepository, UserRepository

logger = logging.getLogger(__name__)

# Default timeout for GitLab API requests
_GITLAB_API_TIMEOUT = 10.0


class GitLabService:
    def __init__(self, gitlab_instance: GitLabInstance):
        """
        Initialize GitLab service for a specific instance.

        Args:
            gitlab_instance: The GitLabInstance model (not SystemSettings)
        """
        self.instance = gitlab_instance
        self.base_url = gitlab_instance.url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v4"
        # Cache key prefix using instance ID (more reliable than URL hash)
        self._cache_key_prefix = f"instance:{gitlab_instance.id}"

    def _get_cache_key(self, suffix: str) -> str:
        """Generate cache key for this specific instance."""
        return f"gitlab:{self._cache_key_prefix}:{suffix}"

    def _get_auth_headers(self) -> Dict[str, str]:
        """Build authentication headers using instance token."""
        if not self.instance.access_token:
            raise ValueError(f"No access token configured for GitLab instance '{self.instance.name}'")
        return {"PRIVATE-TOKEN": self.instance.access_token}

    @asynccontextmanager
    async def _api_client(self) -> AsyncIterator[InstrumentedAsyncClient]:
        """
        Async context manager for authenticated GitLab API client.

        Usage:
            async with self._api_client() as client:
                response = await client.get(url)
        """
        async with InstrumentedAsyncClient("GitLab API", timeout=_GITLAB_API_TIMEOUT) as client:
            yield client

    async def _api_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[httpx.Response]:
        """
        Make an authenticated GET request to the GitLab API.

        Args:
            endpoint: API endpoint (e.g., "/projects/123")
            params: Optional query parameters

        Returns:
            Response object if successful, None if no token configured or request failed
        """
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

    async def _api_post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> Optional[httpx.Response]:
        """
        Make an authenticated POST request to the GitLab API.

        Args:
            endpoint: API endpoint (e.g., "/projects/123/notes")
            json_data: JSON body data

        Returns:
            Response object if successful, None if no token configured or request failed
        """
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

    async def _api_put(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> Optional[httpx.Response]:
        """
        Make an authenticated PUT request to the GitLab API.

        Args:
            endpoint: API endpoint
            json_data: JSON body data

        Returns:
            Response object if successful, None if no token configured or request failed
        """
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
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 10,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Make paginated GET requests to the GitLab API.

        Automatically fetches all pages up to max_pages.

        Args:
            endpoint: API endpoint
            params: Optional query parameters
            max_pages: Maximum number of pages to fetch (default 10, ~1000 items)

        Returns:
            Combined list of all items from all pages, or None on failure
        """
        if not self.instance.access_token:
            return None

        all_items: List[Dict[str, Any]] = []
        page = 1
        per_page = 100  # GitLab max per_page

        try:
            async with self._api_client() as client:
                while page <= max_pages:
                    request_params = {
                        **(params or {}),
                        "page": page,
                        "per_page": per_page,
                    }
                    response = await client.get(
                        f"{self.api_url}{endpoint}",
                        headers=self._get_auth_headers(),
                        params=request_params,
                    )

                    if response.status_code != 200:
                        logger.error(f"GitLab API GET {endpoint} page {page} failed: {response.status_code}")
                        return None

                    items = response.json()
                    if not items:
                        break

                    all_items.extend(items)

                    # Check if there are more pages
                    total_pages = response.headers.get("x-total-pages")
                    if total_pages and page >= int(total_pages):
                        break

                    # If we got fewer items than per_page, we're on the last page
                    if len(items) < per_page:
                        break

                    page += 1

        except Exception as e:
            logger.exception("GitLab API paginated GET %s failed: %s: %s", endpoint, type(e).__name__, e)
            return None

        return all_items

    async def _get_jwks_uri(self) -> Optional[str]:
        """
        Fetches the JWKS URI from the OpenID Connect discovery document.
        Uses Redis cache for multi-pod compatibility.
        """
        cache_key = self._get_cache_key("jwks_uri")

        # Check Redis cache first
        cached_uri = await cache_service.get(cache_key)
        if cached_uri:
            result: str = cached_uri
            return result

        async with InstrumentedAsyncClient("GitLab OIDC", timeout=10.0) as client:
            try:
                # Try OpenID Connect discovery endpoint first
                response = await client.get(f"{self.base_url}/.well-known/openid-configuration")
                if response.status_code == 200:
                    config = response.json()
                    jwks_uri: str | None = config.get("jwks_uri")
                    if jwks_uri:
                        # Cache in Redis for all pods
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
    ) -> Optional[dict]:
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
    ) -> Optional[dict]:
        """Try common fallback JWKS endpoints; returns None if all fail."""
        for path in ["/oauth/discovery/keys", "/-/jwks"]:
            response = await client.get(f"{self.base_url}{path}")
            if response.status_code == 200:
                jwks_fallback: dict[Any, Any] = response.json()
                await cache_service.set(cache_key, jwks_fallback, ttl_seconds=GITLAB_JWKS_CACHE_TTL)
                logger.info(f"JWKS fetched from fallback path: {path}")
                return jwks_fallback
        return None

    async def _try_fetch_jwks_once(self, cache_key: str) -> Optional[dict]:
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

    async def get_jwks(self) -> Optional[dict]:
        """
        Fetches and caches the JWKS from GitLab.
        Uses Redis cache for multi-pod compatibility in Kubernetes.
        """
        cache_key = self._get_cache_key("jwks")

        # Check Redis cache first
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

    async def validate_oidc_token(self, token: str) -> Optional[OIDCPayload]:
        """
        Validates a GitLab OIDC token (JWT).

        Handles key rotation by refreshing JWKS cache if key is not found.
        """
        return await _validate_oidc_token(
            token=token,
            get_jwks=self.get_jwks,
            invalidate_cache=self._invalidate_jwks_cache,
            issuer=self.base_url,
            # `or None` is intentional: normalizes "" -> None so the fail-closed
            # audience guard in _validate_oidc_token rejects unconfigured instances
            # (Finding 7 / W1.1). Do not remove.
            audience=self.instance.oidc_audience or None,
            payload_model=OIDCPayload,
            provider_name="GitLab",
        )

    async def list_branches(self, project_id: int) -> Optional[List[str]]:
        """Fetches all branch names from a GitLab project. Returns None on API failure."""
        branches = await self._api_get_paginated(f"/projects/{project_id}/repository/branches")
        if branches is None:
            return None
        return [b["name"] for b in branches]

    async def get_project_details(self, project_id: int) -> Optional[GitLabProjectDetails]:
        """Fetches project details using the system token."""
        response = await self._api_get(f"/projects/{project_id}")
        if response and response.status_code == 200:
            return GitLabProjectDetails(**response.json())
        return None

    async def get_merge_requests_for_commit(self, project_id: int, commit_sha: str) -> List[GitLabMergeRequest]:
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

    async def get_merge_request_notes(self, project_id: int, mr_iid: int) -> List[GitLabNote]:
        """
        Fetches all notes (comments) from a merge request.

        Uses pagination to fetch all notes (not just first page).
        """
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

    async def get_project_members(self, project_id: int) -> Optional[List[GitLabMember]]:
        """
        Fetches all project members using the system-configured gitlab_access_token.

        Uses pagination to fetch all members (not just first page).
        """
        if not self.instance.access_token:
            logger.warning("Cannot fetch project members: No system GitLab Access Token configured.")
            return None

        # /members/all includes inherited members (from groups)
        members = await self._api_get_paginated(f"/projects/{project_id}/members/all")
        return [GitLabMember(**m) for m in members] if members else None

    async def get_group_members(self, group_id: int) -> Optional[List[GitLabMember]]:
        """
        Fetches all group members using the system-configured gitlab_access_token.

        Uses pagination to fetch all members (not just first page).
        """
        if not self.instance.access_token:
            logger.warning("Cannot fetch group members: No system GitLab Access Token configured.")
            return None

        members = await self._api_get_paginated(f"/groups/{group_id}/members/all")
        return [GitLabMember(**m) for m in members] if members else None

    async def _resolve_group_by_path(self, group_path: str) -> Optional[Dict[str, Any]]:
        """Resolve a GitLab group by its full path. Returns group dict with 'id' key."""
        import urllib.parse

        encoded_path = urllib.parse.quote(group_path, safe="")
        response = await self._api_get(f"/groups/{encoded_path}")
        if response and response.status_code == 200:
            result: Dict[str, Any] = response.json()
            return result
        return None

    async def _resolve_sync_target_group(
        self,
        gitlab_project_id: int,
        gitlab_project_path: str,
        gitlab_project_data: Optional[GitLabProjectDetails],
    ) -> Optional[Tuple[int, str]]:
        """Determine which GitLab group (id, path) should back the team for this project.

        Returns None and logs a reason if the project has no syncable group target.
        """
        if not gitlab_project_data or not gitlab_project_data.namespace:
            logger.warning(
                f"Skipping team sync for project_id={gitlab_project_id} ({gitlab_project_path}): "
                f"no GitLab project details available (likely access denied or 404 on /projects/{gitlab_project_id})."
            )
            return None

        if gitlab_project_data.namespace.kind != "group":
            logger.info(
                f"Skipping team sync for project_id={gitlab_project_id} ({gitlab_project_path}): "
                f"namespace is a user namespace, no group team to sync."
            )
            return None

        namespace = gitlab_project_data.namespace
        group_id = namespace.id
        group_path = namespace.full_path

        # Apply team_sync_depth to determine team granularity.
        # depth=1: "mo/edge/k8s/app" -> team "mo" (top-level only)
        # depth=2: "mo/edge/k8s/app" -> team "mo/edge"
        # depth=0: full path (legacy behavior)
        depth = getattr(self.instance, "team_sync_depth", 1)
        if depth <= 0:
            return group_id, group_path

        parts = group_path.split("/")
        truncated_path = "/".join(parts[:depth])
        if len(parts) <= depth:
            return group_id, truncated_path

        parent_group = await self._resolve_group_by_path(truncated_path)
        if parent_group:
            return parent_group["id"], truncated_path

        # Cannot resolve parent — fall back to the deepest known group consistently.
        # Mixing the truncated *name* with the deep *id* produces a team whose
        # gitlab_group_id doesn't match its name, which corrupts future lookups.
        logger.warning(
            f"Could not resolve GitLab group by path '{truncated_path}' for project_id={gitlab_project_id}. "
            f"Falling back to deepest namespace '{group_path}' (id={group_id}) to keep team data consistent."
        )
        return group_id, group_path

    async def _build_team_members(
        self,
        gitlab_members: List[GitLabMember],
        user_repo: UserRepository,
    ) -> List[TeamMember]:
        """Resolve each GitLab member to a local user (creating one if missing) and map to TeamMember."""
        team_members: List[TeamMember] = []
        for member in gitlab_members:
            user = await self._find_or_create_user(member, user_repo)
            if not user:
                continue
            role = "admin" if member.access_level >= GITLAB_ADMIN_MIN_ACCESS else "member"
            user_id = str(user.get("_id", user.get("id")))
            team_members.append(TeamMember(user_id=user_id, role=role))
        return team_members

    async def _find_or_create_user(
        self,
        member: GitLabMember,
        user_repo: UserRepository,
    ) -> Optional[Dict[str, Any]]:
        user = None
        if member.email:
            user = await user_repo.get_raw_by_email(member.email)
        elif member.username:
            user = await user_repo.get_raw_by_username(member.username)
        if user:
            return user
        if not member.email:
            return None
        new_user = User(
            username=member.username or member.email.split("@")[0],
            email=member.email,
            hashed_password=security.get_password_hash(secrets.token_urlsafe(16)),
            is_active=True,
            auth_provider="gitlab",
        )
        await user_repo.create(new_user)
        return new_user.model_dump()

    async def _upsert_team_with_members(
        self,
        team_repo: TeamRepository,
        existing_team: Optional[Dict[str, Any]],
        team_name: str,
        description: str,
        instance_id: str,
        group_id: int,
        team_members: List[TeamMember],
    ) -> Optional[str]:
        now = datetime.now(timezone.utc)
        if existing_team:
            update_data: dict = {
                "members": [tm.model_dump() for tm in team_members],
                "updated_at": now,
            }
            # Sync name only if it still has the auto-generated GitLab prefix.
            # If the team was manually renamed (e.g. to "BOS"), keep the custom name.
            current_name = existing_team.get("name", "")
            if current_name.startswith("GitLab Group:") and current_name != team_name:
                update_data["name"] = team_name
                update_data["description"] = description
            # Backfill gitlab IDs for legacy teams found by name
            if not existing_team.get("gitlab_group_id"):
                update_data["gitlab_instance_id"] = instance_id
                update_data["gitlab_group_id"] = group_id
            await team_repo.update(existing_team["_id"], update_data)
            return str(existing_team["_id"])
        if team_members:
            new_team = Team(
                name=team_name,
                description=description,
                gitlab_instance_id=instance_id,
                gitlab_group_id=group_id,
                members=team_members,
            )
            await team_repo.create(new_team)
            return str(new_team.id)
        return None

    async def sync_team_from_gitlab(
        self,
        db: AsyncIOMotorDatabase,
        gitlab_project_id: int,
        gitlab_project_path: str,
        gitlab_project_data: Optional[GitLabProjectDetails] = None,
    ) -> Optional[str]:
        """Sync GitLab group members to a local Team and return its id, or None on any failure."""
        team_repo = TeamRepository(db)
        user_repo = UserRepository(db)

        try:
            target = await self._resolve_sync_target_group(gitlab_project_id, gitlab_project_path, gitlab_project_data)
            if target is None:
                return None
            group_id, group_path = target
            team_name = f"GitLab Group: {group_path}"
            description = f"Imported from GitLab Group {group_path}"
            instance_id = str(self.instance.id)

            members = await self.get_group_members(group_id)
            if not members:
                logger.warning(
                    f"Failed to fetch members for group '{team_name}' (group_id={group_id}) "
                    f"while syncing project_id={gitlab_project_id}. Skipping member sync."
                )
                team = await team_repo.get_raw_by_gitlab_group(
                    instance_id, group_id
                ) or await team_repo.get_raw_by_name(team_name)
                if team:
                    return str(team["_id"])
                logger.warning(
                    f"No existing team for group '{team_name}' (group_id={group_id}); "
                    f"project_id={gitlab_project_id} will be left without a team_id."
                )
                return None

            existing_team = await team_repo.get_raw_by_gitlab_group(
                instance_id, group_id
            ) or await team_repo.get_raw_by_name(team_name)
            team_members = await self._build_team_members(members, user_repo)
            return await self._upsert_team_with_members(
                team_repo, existing_team, team_name, description, instance_id, group_id, team_members
            )

        except Exception as e:
            logger.exception(
                "Error syncing GitLab teams for project_id=%s (%s): %s: %s",
                gitlab_project_id,
                gitlab_project_path,
                type(e).__name__,
                e,
            )
            return None
