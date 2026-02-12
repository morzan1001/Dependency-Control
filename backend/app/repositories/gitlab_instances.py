"""
GitLab Instance Repository

Centralizes all database operations for GitLab instances.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.gitlab_instance import GitLabInstance


class GitLabInstanceRepository:
    """Repository for GitLab instance database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.gitlab_instances

    async def get_by_id(self, instance_id: str) -> Optional[GitLabInstance]:
        """Get instance by ID."""
        data = await self.collection.find_one({"_id": instance_id})
        if data:
            return GitLabInstance(**data)
        return None

    async def get_raw_by_id(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get raw instance document by ID."""
        return await self.collection.find_one({"_id": instance_id})

    async def get_by_url(self, url: str) -> Optional[GitLabInstance]:
        """
        Get instance by URL (normalized).
        Handles trailing slashes and protocol variations.
        """
        normalized_url = url.rstrip("/")
        data = await self.collection.find_one({"url": normalized_url})
        if data:
            return GitLabInstance(**data)
        return None

    async def get_default(self) -> Optional[GitLabInstance]:
        """Get the default GitLab instance."""
        data = await self.collection.find_one({"is_default": True, "is_active": True})
        if data:
            return GitLabInstance(**data)
        return None

    async def list_active(self, skip: int = 0, limit: int = 100) -> List[GitLabInstance]:
        """List all active instances."""
        cursor = self.collection.find({"is_active": True}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [GitLabInstance(**doc) for doc in docs]

    async def list_all(self, skip: int = 0, limit: int = 100) -> List[GitLabInstance]:
        """List all instances (including inactive)."""
        cursor = self.collection.find({}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [GitLabInstance(**doc) for doc in docs]

    async def count_active(self) -> int:
        """Count active instances."""
        return await self.collection.count_documents({"is_active": True})

    async def count_all(self) -> int:
        """Count all instances."""
        return await self.collection.count_documents({})

    async def create(self, instance: GitLabInstance) -> GitLabInstance:
        """Create a new instance."""
        doc = instance.model_dump(by_alias=True)
        # access_token has exclude=True (for API responses), but must be stored in MongoDB
        if instance.access_token is not None:
            doc["access_token"] = instance.access_token
        await self.collection.insert_one(doc)
        return instance

    async def update(self, instance_id: str, update_data: Dict[str, Any]) -> bool:
        """
        Update instance fields.
        Returns True if document was modified.
        """
        result = await self.collection.update_one({"_id": instance_id}, {"$set": update_data})
        return result.modified_count > 0

    async def delete(self, instance_id: str) -> bool:
        """
        Delete instance.
        Returns True if document was deleted.

        Note: Should check for dependent projects before deletion.
        """
        result = await self.collection.delete_one({"_id": instance_id})
        return result.deleted_count > 0

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

    async def exists_by_url(self, url: str, exclude_id: Optional[str] = None) -> bool:
        """
        Check if an instance with this URL already exists.
        Optionally exclude a specific instance ID (for updates).
        """
        normalized_url = url.rstrip("/")
        query = {"url": normalized_url}
        if exclude_id:
            query["_id"] = {"$ne": exclude_id}

        count = await self.collection.count_documents(query)
        return count > 0

    async def exists_by_name(self, name: str, exclude_id: Optional[str] = None) -> bool:
        """
        Check if an instance with this name already exists.
        Optionally exclude a specific instance ID (for updates).
        """
        query = {"name": name}
        if exclude_id:
            query["_id"] = {"$ne": exclude_id}

        count = await self.collection.count_documents(query)
        return count > 0
