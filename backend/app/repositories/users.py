"""Repository for user database operations."""

import re
from typing import Any, Dict, List, Optional

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
        return await self.find_one_raw({"username": username})

    async def get_raw_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return await self.find_one_raw({"email": email})

    async def get_raw_by_email_ci(self, email: str) -> Optional[Dict[str, Any]]:
        """Case-insensitive email lookup. Stored emails are not normalised and the unique
        index is not collated, so an exact match can silently fail to resolve a real user
        whose address differs only in case (e.g. GitLab returns ``Alice@Corp.com`` while the
        login stored ``alice@corp.com``)."""
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one(
                {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}
            )

    async def get_first_admin(self) -> Optional[Dict[str, Any]]:
        """Return the first user holding the system:manage permission."""
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"permissions": "system:manage"})

    async def find_by_ids(self, user_ids: List[str]) -> List[Dict[str, Any]]:
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find({"_id": {"$in": user_ids}})
            return await cursor.to_list(None)

    async def exists_by_username(self, username: str) -> bool:
        return await self.exists({"username": username})

    async def exists_by_email(self, email: str) -> bool:
        return await self.exists({"email": email})
