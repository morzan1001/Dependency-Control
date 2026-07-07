"""Repository for GitLab instances."""

from typing import Optional

from app.models.gitlab_instance import GitLabInstance
from app.repositories.vcs_instances import VcsInstanceRepository


class GitLabInstanceRepository(VcsInstanceRepository[GitLabInstance]):
    """Repository for GitLab instance database operations."""

    collection_name = "gitlab_instances"
    model_class = GitLabInstance

    async def get_default(self) -> Optional[GitLabInstance]:
        """Get the default GitLab instance."""
        data = await self.collection.find_one({"is_default": True, "is_active": True})
        if data:
            return GitLabInstance(**data)
        return None

    async def set_as_default(self, instance_id: str) -> bool:
        """
        Set an instance as the default and unset all others.
        Returns True if successful.
        """
        # First, unset all defaults
        await self.collection.update_many({}, {"$set": {"is_default": False}})

        # Then set the specified instance as default
        result = await self.collection.update_one({"_id": instance_id}, {"$set": {"is_default": True}})
        return result.modified_count > 0
