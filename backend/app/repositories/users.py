"""Repository for user database operations."""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import track_db_operation
from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    collection_name = "users"
    model_class = User

    async def get_by_username(self, username: str) -> Optional[User]:
        with track_db_operation(self.collection_name, "find_one"):
            data = await self.collection.find_one({"username": username})
        return self._to_model(data)

    async def get_by_email(self, email: str) -> Optional[User]:
        with track_db_operation(self.collection_name, "find_one"):
            data = await self.collection.find_one({"email": email})
        return self._to_model(data)

    async def get_raw_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"username": username})

    async def get_raw_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"email": email})

    async def get_first_admin(self) -> Optional[Dict[str, Any]]:
        """Return the first user holding the system:manage permission."""
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"permissions": "system:manage"})

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "username",
        sort_order: int = 1,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[User]:
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query, projection).sort(sort_by, sort_order).skip(skip).limit(limit)
            docs = await cursor.to_list(limit)
        return self._to_model_list(docs)

    async def find_by_ids(self, user_ids: List[str]) -> List[Dict[str, Any]]:
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find({"_id": {"$in": user_ids}})
            return await cursor.to_list(2000)

    async def exists_by_username(self, username: str) -> bool:
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"username": username}, {"_id": 1}) is not None

    async def exists_by_email(self, email: str) -> bool:
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"email": email}, {"_id": 1}) is not None
