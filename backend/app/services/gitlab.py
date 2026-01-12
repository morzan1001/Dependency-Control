import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from jose import jwt

from app.core import security
from app.models.system import SystemSettings
from app.models.team import Team, TeamMember
from app.models.user import User

logger = logging.getLogger(__name__)


class GitLabService:
    def __init__(self, settings: SystemSettings):
        self.settings = settings
        self.base_url = settings.gitlab_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v4"
        self._jwks_cache = None
        self._jwks_cache_time = 0.0
        self._jwks_uri_cache = None

    async def _get_jwks_uri(self) -> Optional[str]:
        """
        Fetches the JWKS URI from the OpenID Connect discovery document.
        """
        if self._jwks_uri_cache:
            return self._jwks_uri_cache

        async with httpx.AsyncClient() as client:
            try:
                # Try OpenID Connect discovery endpoint first
                response = await client.get(
                    f"{self.base_url}/.well-known/openid-configuration", timeout=10.0
                )
                if response.status_code == 200:
                    config = response.json()
                    self._jwks_uri_cache = config.get("jwks_uri")
                    return self._jwks_uri_cache
            except Exception as e:
                logger.warning(f"Error fetching OIDC discovery: {e}")

        return None

    async def get_jwks(self) -> Optional[dict]:
        """
        Fetches and caches the JWKS from GitLab.
        """
        # Simple caching mechanism (e.g. 1 hour)
        now = datetime.now(timezone.utc).timestamp()
        if self._jwks_cache and (now - self._jwks_cache_time < 3600):
            return self._jwks_cache

        async with httpx.AsyncClient() as client:
            try:
                # Try to get JWKS URI from discovery document
                jwks_uri = await self._get_jwks_uri()

                if jwks_uri:
                    response = await client.get(jwks_uri, timeout=10.0)
                    if response.status_code == 200:
                        self._jwks_cache = response.json()
                        self._jwks_cache_time = now
                        return self._jwks_cache

                # Fallback: Try common JWKS endpoints
                for path in ["/-/jwks", "/oauth/discovery/keys"]:
                    response = await client.get(f"{self.base_url}{path}", timeout=10.0)
                    if response.status_code == 200:
                        self._jwks_cache = response.json()
                        self._jwks_cache_time = now
                        logger.info(f"JWKS fetched from fallback path: {path}")
                        return self._jwks_cache

                logger.error("Failed to fetch JWKS from any known endpoint")
            except Exception as e:
                logger.error(f"Error fetching JWKS: {e}")
        return {}

    async def validate_oidc_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validates a GitLab OIDC token (JWT).
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

            if not key:
                logger.error(f"No matching key found for kid: {kid}")
                return None

            # 4. Verify
            # Verify issuer and optionally audience if configured
            jwt_options = {}
            if self.settings.gitlab_oidc_audience:
                jwt_options["verify_aud"] = True
            else:
                # Audience verification disabled - tokens from other apps could be accepted
                # Consider configuring gitlab_oidc_audience in system settings
                jwt_options["verify_aud"] = False

            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.settings.gitlab_url,
                audience=(
                    self.settings.gitlab_oidc_audience
                    if self.settings.gitlab_oidc_audience
                    else None
                ),
                options=jwt_options,
            )
            return payload
        except Exception as e:
            logger.error(f"OIDC Token validation error: {e}")
            return None

    async def get_project_details(self, project_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetches project details using the system token.
        """
        if not self.settings.gitlab_access_token:
            return None

        auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.api_url}/projects/{project_id}",
                    headers=auth_headers,
                    timeout=10.0,
                )
                if response.status_code == 200:
                    return response.json()
                return None
            except Exception:
                return None

    async def get_merge_requests_for_commit(
        self, project_id: int, commit_sha: str
    ) -> List[Dict[str, Any]]:
        """
        Fetches merge requests associated with a specific commit.
        """
        if not self.settings.gitlab_access_token:
            return []

        auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.api_url}/projects/{project_id}/repository/commits/{commit_sha}/merge_requests",
                    headers=auth_headers,
                    timeout=10.0,
                )
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                logger.error(f"Error fetching MRs for commit {commit_sha}: {e}")
        return []

    async def post_merge_request_comment(
        self, project_id: int, mr_iid: int, body: str
    ) -> bool:
        """
        Posts a comment to a merge request.
        """
        if not self.settings.gitlab_access_token:
            return False

        auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/notes",
                    headers=auth_headers,
                    json={"body": body},
                    timeout=10.0,
                )
                if response.status_code == 201:
                    return True
                else:
                    logger.error(
                        f"Failed to post MR comment: {response.status_code} - {response.text}"
                    )
            except Exception as e:
                logger.error(f"Error posting MR comment: {e}")
        return False

    async def get_merge_request_notes(
        self, project_id: int, mr_iid: int
    ) -> List[Dict[str, Any]]:
        """
        Fetches notes (comments) from a merge request.
        """
        if not self.settings.gitlab_access_token:
            return []

        auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/notes",
                    headers=auth_headers,
                    timeout=10.0,
                )
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(
                        f"Failed to fetch MR notes: {response.status_code} - {response.text}"
                    )
            except Exception as e:
                logger.error(f"Error fetching MR notes: {e}")
        return []

    async def update_merge_request_comment(
        self, project_id: int, mr_iid: int, note_id: int, body: str
    ) -> bool:
        """
        Updates an existing comment on a merge request.
        """
        if not self.settings.gitlab_access_token:
            return False

        auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.put(
                    f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/notes/{note_id}",
                    headers=auth_headers,
                    json={"body": body},
                    timeout=10.0,
                )
                if response.status_code == 200:
                    return True
                else:
                    logger.error(
                        f"Failed to update MR comment: {response.status_code} - {response.text}"
                    )
            except Exception as e:
                logger.error(f"Error updating MR comment: {e}")
        return False

    async def get_project_members(
        self, project_id: int
    ) -> Optional[list[Dict[str, Any]]]:
        """
        Fetches project members using the system-configured gitlab_access_token.
        """
        if not self.settings.gitlab_access_token:
            logger.warning(
                "Cannot fetch project members: No system GitLab Access Token configured."
            )
            return None

        auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                # /members/all includes inherited members (from groups)
                response = await client.get(
                    f"{self.api_url}/projects/{project_id}/members/all",
                    headers=auth_headers,
                    timeout=10.0,
                )
                if response.status_code == 200:
                    return response.json()

                logger.error(
                    f"Failed to fetch GitLab members: {response.status_code} {response.text}"
                )
                return None
            except Exception as e:
                logger.error(f"Error fetching GitLab members: {e}")
                return None

    async def get_group_members(self, group_id: int) -> Optional[list[Dict[str, Any]]]:
        """
        Fetches group members using the system-configured gitlab_access_token.
        """
        if not self.settings.gitlab_access_token:
            logger.warning(
                "Cannot fetch group members: No system GitLab Access Token configured."
            )
            return None

        auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.api_url}/groups/{group_id}/members/all",
                    headers=auth_headers,
                    timeout=10.0,
                )
                if response.status_code == 200:
                    return response.json()
                logger.error(
                    f"Failed to fetch GitLab group members: {response.status_code} {response.text}"
                )
                return None
            except Exception as e:
                logger.error(f"Error fetching GitLab group members: {e}")
                return None

    async def sync_team_from_gitlab(
        self,
        db,
        gitlab_project_id: int,
        gitlab_project_path: str,
        gitlab_project_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Syncs GitLab project members to a local Team.
        Returns the Team ID.
        """
        try:
            members = None

            # Only sync if it's a group
            if (
                gitlab_project_data
                and gitlab_project_data.get("namespace", {}).get("kind") == "group"
            ):
                namespace = gitlab_project_data["namespace"]
                group_id = namespace["id"]
                group_path = namespace["full_path"]
                team_name = f"GitLab Group: {group_path}"
                description = f"Imported from GitLab Group {group_path}"

                members = await self.get_group_members(group_id)
            else:
                # Not a group project (e.g. user namespace), skip sync
                return None

            if not members:
                logger.warning(
                    f"Failed to fetch members for group {team_name}. Skipping sync."
                )
                # Try to find existing team to return its ID at least
                existing_team = await db.teams.find_one({"name": team_name})
                if existing_team:
                    return str(existing_team["_id"])
                return None

            if not members:
                return None

            # Create or Update Team
            team = await db.teams.find_one({"name": team_name})

            team_members = []
            for member in members:
                member_email = member.get("email")
                member_username = member.get("username")

                user = None
                if member_email:
                    user = await db.users.find_one({"email": member_email})
                elif member_username:
                    user = await db.users.find_one({"username": member_username})

                if not user and member_email:
                    # Create new user
                    user = User(
                        username=member_username or member_email.split("@")[0],
                        email=member_email,
                        hashed_password=security.get_password_hash(
                            secrets.token_urlsafe(16)
                        ),
                        is_active=True,
                        auth_provider="gitlab",
                    )
                    await db.users.insert_one(user.dict(by_alias=True))
                    user = user.dict(by_alias=True)

                if user:
                    # Map GitLab access level to role
                    # 10: Guest, 20: Reporter, 30: Developer, 40: Maintainer, 50: Owner
                    access_level = member.get("access_level", 0)
                    role = "member"
                    if access_level >= 40:
                        role = "admin"

                    team_members.append(TeamMember(user_id=str(user["_id"]), role=role))

            if team:
                await db.teams.update_one(
                    {"_id": team["_id"]},
                    {
                        "$set": {
                            "members": [tm.dict() for tm in team_members],
                            "updated_at": datetime.now(timezone.utc),
                        }
                    },
                )
                return str(team["_id"])
            elif team_members:
                new_team = Team(
                    name=team_name, description=description, members=team_members
                )
                result = await db.teams.insert_one(new_team.dict(by_alias=True))
                return str(result.inserted_id)

        except Exception as e:
            logger.error(f"Error syncing GitLab teams: {e}")
            return None

        return None
