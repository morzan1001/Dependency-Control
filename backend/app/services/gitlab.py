import httpx
from typing import Optional, Dict, Any
from app.models.system import SystemSettings

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
                print(f"Error validating GitLab token: {e}")
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
                print(f"Failed to fetch GitLab members: {response.status_code} {response.text}")
                return None
            except Exception as e:
                print(f"Error fetching GitLab members: {e}")
                return None
