"""Repository for user database operations."""

import re
from typing import Any

from app.core.metrics import track_db_operation
from app.models.user import User
from app.repositories.base import BaseRepository


def _email_query(email: str) -> dict[str, Any]:
    """Case-insensitive: emails stored before normalisation keep their case and the index isn't collated."""
    return {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}


class UserRepository(BaseRepository[User]):
    collection_name = "users"
    model_class = User

    async def get_raw_by_username(self, username: str) -> dict[str, Any] | None:
        return await self.find_one_raw({"username": username})

    async def get_raw_by_email(self, email: str) -> dict[str, Any] | None:
        return await self.find_one_raw(_email_query(email))

    async def get_raw_by_verified_email(self, email: str) -> dict[str, Any] | None:
        """The lookup identity matching must use: an unverified address names whoever typed it."""
        return await self.find_one_raw({**_email_query(email), "is_verified": True})

    async def find_by_ids(self, user_ids: list[str]) -> list[dict[str, Any]]:
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find({"_id": {"$in": user_ids}})
            return await cursor.to_list(None)

    async def exists_by_username(self, username: str) -> bool:
        return await self.exists({"username": username})

    async def exists_by_email(self, email: str) -> bool:
        return await self.exists(_email_query(email))
