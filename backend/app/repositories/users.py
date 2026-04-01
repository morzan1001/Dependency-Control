"""
User Repository

Centralizes all database operations for users.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import track_db_operation
from app.models.user import User

_COL = "users"


class UserRepository:
    """Repository for user database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.users

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": user_id})
        if data:
            return User(**data)
        return None

    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"username": username})
        if data:
            return User(**data)
        return None

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"email": email})
        if data:
            return User(**data)
        return None

    async def get_raw_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get raw user document by ID."""
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"_id": user_id})

    async def get_raw_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get raw user document by username."""
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"username": username})

    async def get_raw_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get raw user document by email."""
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"email": email})

    async def get_first_admin(self) -> Optional[Dict[str, Any]]:
        """Get the first user with system:manage permission."""
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"permissions": "system:manage"})

    async def create(self, user: User) -> User:
        """Create a new user."""
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(user.model_dump(by_alias=True))
        return user

    async def update(self, user_id: str, update_data: Dict[str, Any]) -> Optional[User]:
        """Update user by ID."""
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one({"_id": user_id}, {"$set": update_data})
        return await self.get_by_id(user_id)

    async def delete(self, user_id: str) -> bool:
        """Delete user by ID."""
        with track_db_operation(_COL, "delete_one"):
            result = await self.collection.delete_one({"_id": user_id})
        return result.deleted_count > 0

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "username",
        sort_order: int = 1,
    ) -> List[User]:
        """Find multiple users with pagination. Returns Pydantic models."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
            docs = await cursor.to_list(limit)
        return [User(**doc) for doc in docs]

    async def find_by_ids(self, user_ids: List[str]) -> List[Dict[str, Any]]:
        """Find users by list of IDs."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find({"_id": {"$in": user_ids}})
            return await cursor.to_list(None)

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count users matching query."""
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(query or {})

    async def exists_by_username(self, username: str) -> bool:
        """Check if username exists."""
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"username": username}, {"_id": 1}) is not None

    async def exists_by_email(self, email: str) -> bool:
        """Check if email exists."""
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"email": email}, {"_id": 1}) is not None

