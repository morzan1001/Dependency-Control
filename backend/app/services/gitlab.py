import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from jose import jwt

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
            logger.error(f"GitLab API GET {endpoint} failed: {e}")
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
            logger.error(f"GitLab API POST {endpoint} failed: {e}")
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
            logger.error(f"GitLab API PUT {endpoint} failed: {e}")
            return None

    async def _api_get_paginated(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Make paginated GET requests to the GitLab API.

        Automatically fetches all pages up to max_pages.

        Args:
            endpoint: API endpoint
            params: Optional query parameters
            max_pages: Maximum number of pages to fetch (default 10, ~1000 items)

        Returns:
            Combined list of all items from all pages
        """
        if not self.instance.access_token:
            return []

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
                        break

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
            logger.error(f"GitLab API paginated GET {endpoint} failed: {e}")

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
            return cached_uri

        async with InstrumentedAsyncClient("GitLab OIDC", timeout=10.0) as client:
            try:
                # Try OpenID Connect discovery endpoint first
                response = await client.get(f"{self.base_url}/.well-known/openid-configuration")
                if response.status_code == 200:
                    config = response.json()
                    jwks_uri = config.get("jwks_uri")
                    if jwks_uri:
                        # Cache in Redis for all pods
                        await cache_service.set(cache_key, jwks_uri, ttl_seconds=GITLAB_JWKS_URI_CACHE_TTL)
                    return jwks_uri
            except Exception as e:
                logger.warning(f"Error fetching OIDC discovery: {e}")

        return None

    async def get_jwks(self) -> Optional[dict]:
        """
        Fetches and caches the JWKS from GitLab.
        Uses Redis cache for multi-pod compatibility in Kubernetes.
        """
        cache_key = self._get_cache_key("jwks")

        # Check Redis cache first
        cached_jwks = await cache_service.get(cache_key)
        if cached_jwks:
            return cached_jwks

        async with InstrumentedAsyncClient("GitLab JWKS", timeout=10.0) as client:
            try:
                # Try to get JWKS URI from discovery document
                jwks_uri = await self._get_jwks_uri()

                if jwks_uri:
                    response = await client.get(jwks_uri)
                    if response.status_code == 200:
                        jwks = response.json()
                        # Cache in Redis for all pods
                        await cache_service.set(cache_key, jwks, ttl_seconds=GITLAB_JWKS_CACHE_TTL)
                        return jwks

                # Fallback: Try common JWKS endpoints
                for path in ["/-/jwks", "/oauth/discovery/keys"]:
                    response = await client.get(f"{self.base_url}{path}")
                    if response.status_code == 200:
                        jwks = response.json()
                        # Cache in Redis for all pods
                        await cache_service.set(cache_key, jwks, ttl_seconds=GITLAB_JWKS_CACHE_TTL)
                        logger.info(f"JWKS fetched from fallback path: {path}")
                        return jwks

                logger.error("Failed to fetch JWKS from any known endpoint")
            except Exception as e:
                logger.error(f"Error fetching JWKS: {e}")
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
        try:
            # 1. Get Key ID from Header
            headers = jwt.get_unverified_header(token)
            kid = headers.get("kid")
            if not kid:
                logger.warning("OIDC Token missing 'kid' in header")
                return None

            # 2. Fetch JWKS
            jwks = await self.get_jwks()

            # 3. Find Key
            key = None
            for k in jwks.get("keys", []):
                if k.get("kid") == kid:
                    key = k
                    break

            # 4. If key not found, try refreshing cache (key rotation scenario)
            if not key:
                logger.info(f"Key {kid} not in cache, refreshing JWKS...")
                await self._invalidate_jwks_cache()
                jwks = await self.get_jwks()

                for k in jwks.get("keys", []):
                    if k.get("kid") == kid:
                        key = k
                        break

            if not key:
                logger.error(f"No matching key found for kid: {kid} after refresh")
                return None

            # 4. Verify
            # Verify issuer and optionally audience if configured
            jwt_options = {}
            if self.instance.oidc_audience:
                jwt_options["verify_aud"] = True
            else:
                # Audience verification disabled - tokens from other apps could be accepted
                # Consider configuring oidc_audience for this GitLab instance
                jwt_options["verify_aud"] = False

            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.base_url,
                audience=(self.instance.oidc_audience if self.instance.oidc_audience else None),
                options=jwt_options,
            )
            return OIDCPayload(**payload)
        except Exception as e:
            logger.error(f"OIDC Token validation error: {e}")
            return None

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
        return [GitLabNote(**n) for n in notes]

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

    async def sync_team_from_gitlab(
        self,
        db: AsyncIOMotorDatabase,
        gitlab_project_id: int,
        gitlab_project_path: str,  # Currently unused, kept for API compatibility
        gitlab_project_data: Optional[GitLabProjectDetails] = None,
    ) -> Optional[str]:
        """
        Syncs GitLab project members to a local Team.

        Args:
            db: Database connection
            gitlab_project_id: GitLab project ID
            gitlab_project_path: GitLab project path (currently unused)
            gitlab_project_data: Optional project data from GitLab API

        Returns:
            Team ID if sync successful, None otherwise
        """
        _ = gitlab_project_path  # Suppress unused parameter warning
        team_repo = TeamRepository(db)
        user_repo = UserRepository(db)

        try:
            members = None

            # Only sync if it's a group
            if gitlab_project_data and gitlab_project_data.namespace and gitlab_project_data.namespace.kind == "group":
                namespace = gitlab_project_data.namespace
                group_id = namespace.id
                group_path = namespace.full_path
                team_name = f"GitLab Group: {group_path}"
                description = f"Imported from GitLab Group {group_path}"

                members = await self.get_group_members(group_id)
            else:
                # Not a group project (e.g. user namespace), skip sync
                return None

            instance_id = str(self.instance.id)

            if not members:
                logger.warning(f"Failed to fetch members for group {team_name}. Skipping sync.")
                # Try to find existing team to return its ID at least
                team = await team_repo.get_raw_by_gitlab_group(
                    instance_id, group_id
                ) or await team_repo.get_raw_by_name(team_name)
                if team:
                    return str(team["_id"])
                return None

            # Find existing team by GitLab group ID (rename-safe) or fallback to name
            team = await team_repo.get_raw_by_gitlab_group(instance_id, group_id) or await team_repo.get_raw_by_name(
                team_name
            )

            team_members = []
            for member in members:
                user = None
                if member.email:
                    user = await user_repo.get_raw_by_email(member.email)
                elif member.username:
                    user = await user_repo.get_raw_by_username(member.username)

                if not user and member.email:
                    # Create new user
                    new_user = User(
                        username=member.username or member.email.split("@")[0],
                        email=member.email,
                        hashed_password=security.get_password_hash(secrets.token_urlsafe(16)),
                        is_active=True,
                        auth_provider="gitlab",
                    )
                    await user_repo.create(new_user)
                    user = new_user.model_dump()

                if user:
                    # Map GitLab access level to role
                    # See constants: GITLAB_ACCESS_GUEST (10), REPORTER (20), etc.
                    role = "member"
                    if member.access_level >= GITLAB_ADMIN_MIN_ACCESS:
                        role = "admin"

                    user_id = str(user.get("_id", user.get("id")))
                    team_members.append(TeamMember(user_id=user_id, role=role))

            now = datetime.now(timezone.utc)
            if team:
                update_data: dict = {
                    "members": [tm.model_dump() for tm in team_members],
                    "updated_at": now,
                }
                # Sync name if group was renamed
                if team.get("name") != team_name:
                    update_data["name"] = team_name
                    update_data["description"] = description
                # Backfill gitlab IDs for legacy teams found by name
                if not team.get("gitlab_group_id"):
                    update_data["gitlab_instance_id"] = instance_id
                    update_data["gitlab_group_id"] = group_id
                await team_repo.update(team["_id"], update_data)
                return str(team["_id"])
            elif team_members:
                new_team = Team(
                    name=team_name,
                    description=description,
                    gitlab_instance_id=instance_id,
                    gitlab_group_id=group_id,
                    members=team_members,
                )
                await team_repo.create(new_team)
                return str(new_team.id)

        except Exception as e:
            logger.error(f"Error syncing GitLab teams: {e}")
            return None

        return None
