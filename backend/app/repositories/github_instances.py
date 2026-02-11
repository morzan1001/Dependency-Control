"""
GitHub Instance Repository

Centralizes all database operations for GitHub instances.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.github_instance import GitHubInstance


class GitHubInstanceRepository:
    """Repository for GitHub instance database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.github_instances

    async def get_by_id(self, instance_id: str) -> Optional[GitHubInstance]:
        """Get instance by ID."""
        data = await self.collection.find_one({"_id": instance_id})
        if data:
            return GitHubInstance(**data)
        return None

    async def get_raw_by_id(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get raw instance document by ID."""
        return await self.collection.find_one({"_id": instance_id})

    async def get_by_url(self, url: str) -> Optional[GitHubInstance]:
        """
        Get instance by URL (normalized).
        Handles trailing slashes.
        """
        normalized_url = url.rstrip("/")
        data = await self.collection.find_one({"url": normalized_url})
        if data:
            return GitHubInstance(**data)
        return None

    async def list_active(self, skip: int = 0, limit: int = 100) -> List[GitHubInstance]:
        """List all active instances."""
        cursor = self.collection.find({"is_active": True}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [GitHubInstance(**doc) for doc in docs]

    async def list_all(self, skip: int = 0, limit: int = 100) -> List[GitHubInstance]:
        """List all instances (including inactive)."""
        cursor = self.collection.find({}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [GitHubInstance(**doc) for doc in docs]

    async def count_active(self) -> int:
        """Count active instances."""
        return await self.collection.count_documents({"is_active": True})

    async def count_all(self) -> int:
        """Count all instances."""
        return await self.collection.count_documents({})

    async def create(self, instance: GitHubInstance) -> GitHubInstance:
        """Create a new instance."""
        await self.collection.insert_one(instance.model_dump(by_alias=True))
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

    async def exists_by_url(self, url: str, exclude_id: Optional[str] = None) -> bool:
        """
        Check if an instance with this URL already exists.
        Optionally exclude a specific instance ID (for updates).
        """
        normalized_url = url.rstrip("/")
        query: Dict[str, Any] = {"url": normalized_url}
        if exclude_id:
            query["_id"] = {"$ne": exclude_id}
        return await self.collection.count_documents(query) > 0

    async def exists_by_name(self, name: str, exclude_id: Optional[str] = None) -> bool:
        """
        Check if an instance with this name already exists.
        Optionally exclude a specific instance ID (for updates).
        """
        query: Dict[str, Any] = {"name": name}
        if exclude_id:
            query["_id"] = {"$ne": exclude_id}
        return await self.collection.count_documents(query) > 0
