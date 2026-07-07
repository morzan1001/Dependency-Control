"""Generic base repository for VCS (GitLab/GitHub) instances.

GitLab and GitHub instance repositories share an identical set of CRUD, list,
count and existence-check operations over their respective collections. This
base holds that shared behavior; subclasses only supply ``collection_name`` and
``model_class`` (mirroring how :class:`app.repositories.base.BaseRepository` is
parameterized).
"""

from typing import Any, Dict, List, Optional, Type

from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel


class VcsInstanceRepository[T: BaseModel]:
    """Generic repository for VCS instance database operations.

    Subclasses set ``collection_name`` and ``model_class``.
    """

    collection_name: str
    model_class: Type[T]

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db[self.collection_name]

    async def get_by_id(self, instance_id: str) -> Optional[T]:
        data = await self.collection.find_one({"_id": instance_id})
        if data:
            return self.model_class(**data)
        return None

    async def get_raw_by_id(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get raw instance document by ID."""
        return await self.collection.find_one({"_id": instance_id})

    async def get_by_url(self, url: str) -> Optional[T]:
        """
        Get instance by URL (normalized).
        Handles trailing slashes.
        """
        normalized_url = url.rstrip("/")
        data = await self.collection.find_one({"url": normalized_url})
        if data:
            return self.model_class(**data)
        return None

    async def list_active(self, skip: int = 0, limit: int = 100) -> List[T]:
        cursor = self.collection.find({"is_active": True}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [self.model_class(**doc) for doc in docs]

    async def list_all(self, skip: int = 0, limit: int = 100) -> List[T]:
        """List all instances (including inactive)."""
        cursor = self.collection.find({}).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [self.model_class(**doc) for doc in docs]

    async def count_active(self) -> int:
        return await self.collection.count_documents({"is_active": True})

    async def count_all(self) -> int:
        return await self.collection.count_documents({})

    async def create(self, instance: T) -> T:
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

    async def exists_by_url(self, url: str, exclude_id: Optional[str] = None) -> bool:
        """
        Check if an instance with this URL already exists.
        Optionally exclude a specific instance ID (for updates).
        """
        normalized_url = url.rstrip("/")
        query: Dict[str, Any] = {"url": normalized_url}
        if exclude_id:
            query["_id"] = {"$ne": exclude_id}
        return await self.collection.find_one(query, {"_id": 1}) is not None

    async def exists_by_name(self, name: str, exclude_id: Optional[str] = None) -> bool:
        """
        Check if an instance with this name already exists.
        Optionally exclude a specific instance ID (for updates).
        """
        query: Dict[str, Any] = {"name": name}
        if exclude_id:
            query["_id"] = {"$ne": exclude_id}
        return await self.collection.find_one(query, {"_id": 1}) is not None
