import httpx
import secrets
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from app.models.system import SystemSettings
from app.models.team import Team, TeamMember
from app.models.user import User
from app.core import security

logger = logging.getLogger(__name__)

class GitLabService:
    def __init__(self, settings: SystemSettings):
        self.settings = settings
        self.base_url = settings.gitlab_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v4"

    async def validate_job_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validates the CI_JOB_TOKEN by calling GitLab's /job endpoint.
        Returns the job details if valid, None otherwise.
        """
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.api_url}/job",
                    headers={"JOB-TOKEN": token},
                    timeout=10.0
                )
                if response.status_code == 200:
                    return response.json()
                return None
            except Exception as e:
                logger.error(f"Error validating GitLab token: {e}")
                return None

    async def get_project_details(self, project_id: int, token: str) -> Optional[Dict[str, Any]]:
        """
        Fetches project details using the token.
        """
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.api_url}/projects/{project_id}",
                    headers={"JOB-TOKEN": token},
                    timeout=10.0
                )
                if response.status_code == 200:
                    return response.json()
                return None
            except Exception:
                return None

    async def get_project_members(self, project_id: int, token: str) -> Optional[list[Dict[str, Any]]]:
        """
        Fetches project members. Tries to use the provided token (CI_JOB_TOKEN),
        but falls back to the system-configured gitlab_access_token if available and needed.
        """
        # Determine which token to use. CI_JOB_TOKEN often has limited permissions.
        # If a system-wide access token is configured, it's more reliable for fetching members.
        auth_headers = {"JOB-TOKEN": token}
        if self.settings.gitlab_access_token:
            auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                # /members/all includes inherited members (from groups)
                response = await client.get(
                    f"{self.api_url}/projects/{project_id}/members/all",
                    headers=auth_headers,
                    timeout=10.0
                )
                if response.status_code == 200:
                    return response.json()
                
                # If failed with system token, or if we didn't use it, try the other one?
                # For now, just return None if it fails.
                logger.error(f"Failed to fetch GitLab members: {response.status_code} {response.text}")
                return None
            except Exception as e:
                logger.error(f"Error fetching GitLab members: {e}")
                return None

    async def get_group_members(self, group_id: int, token: str) -> Optional[list[Dict[str, Any]]]:
        """
        Fetches group members.
        """
        auth_headers = {"JOB-TOKEN": token}
        if self.settings.gitlab_access_token:
            auth_headers = {"PRIVATE-TOKEN": self.settings.gitlab_access_token}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.api_url}/groups/{group_id}/members/all",
                    headers=auth_headers,
                    timeout=10.0
                )
                if response.status_code == 200:
                    return response.json()
                logger.error(f"Failed to fetch GitLab group members: {response.status_code} {response.text}")
                return None
            except Exception as e:
                logger.error(f"Error fetching GitLab group members: {e}")
                return None

    async def sync_team_from_gitlab(self, db, gitlab_project_id: int, gitlab_project_path: str, token: str, gitlab_project_data: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Syncs GitLab project members to a local Team.
        Returns the Team ID.
        """
        try:
            members = None
            
            # Only sync if it's a group
            if gitlab_project_data and gitlab_project_data.get("namespace", {}).get("kind") == "group":
                namespace = gitlab_project_data["namespace"]
                group_id = namespace["id"]
                group_path = namespace["full_path"]
                team_name = f"GitLab Group: {group_path}"
                description = f"Imported from GitLab Group {group_path}"
                
                members = await self.get_group_members(group_id, token)
            else:
                # Not a group project (e.g. user namespace), skip sync
                return None
            
            if not members:
                 logger.warning(f"Failed to fetch members for group {team_name}. Skipping sync.")
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
                        hashed_password=security.get_password_hash(secrets.token_urlsafe(16)),
                        is_active=True,
                        auth_provider="gitlab"
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
                    {"$set": {"members": [tm.dict() for tm in team_members], "updated_at": datetime.utcnow()}}
                )
                return str(team["_id"])
            elif team_members:
                new_team = Team(
                    name=team_name,
                    description=description,
                    members=team_members
                )
                result = await db.teams.insert_one(new_team.dict(by_alias=True))
                return str(result.inserted_id)
                
        except Exception as e:
            logger.error(f"Error syncing GitLab teams: {e}")
            return None
        
        return None
