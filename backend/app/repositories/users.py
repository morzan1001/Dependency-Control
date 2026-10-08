"""Repository for user database operations."""

import re
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Any

from pymongo.errors import DuplicateKeyError

from app.models.user import User
from app.repositories.base import BaseRepository

_TAKEN = {"email": "Email already registered", "username": "Username already taken"}


class IdentityTakenError(Exception):
    """Another account holds this email or username; the API answers 400 with the message."""

    def __init__(self, field: str) -> None:
        super().__init__(_TAKEN[field])


def _email_query(email: str) -> dict[str, Any]:
    """Case-insensitive: emails stored before normalisation keep their case and the index isn't collated."""
    return {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}


@contextmanager
def _unique_index_as_identity_taken() -> Iterator[None]:
    try:
        yield
    except DuplicateKeyError as exc:
        field = next(iter((exc.details or {}).get("keyPattern") or {}), None)
        if field not in _TAKEN:
            raise
        raise IdentityTakenError(field) from exc


class UserRepository(BaseRepository[User]):
    collection_name = "users"
    model_class = User

    async def create(self, model: User) -> User:
        # The unique index compares exactly, so only this check sees a case variant of a stored address.
        if await self.exists_by_email(model.email):
            raise IdentityTakenError("email")
        with _unique_index_as_identity_taken():
            return await super().create(model)

    async def update(self, id: str, update_data: dict[str, Any]) -> User | None:
        if "email" in update_data and await self.exists({"_id": {"$ne": id}, **_email_query(update_data["email"])}):
            raise IdentityTakenError("email")
        with _unique_index_as_identity_taken():
            return await super().update(id, update_data)

    async def claim_totp_step(self, user_id: str, step: int) -> bool:
        """Spend ``step``; False when it or a later step was already spent."""
        return await self.update_raw(
            user_id, {"$set": {"totp_last_step": step}}, guard={"totp_last_step": {"$not": {"$gte": step}}}
        )

    async def get_raw_by_username(self, username: str) -> dict[str, Any] | None:
        return await self.find_one_raw({"username": username})

    async def get_raw_by_email(self, email: str) -> dict[str, Any] | None:
        return await self.find_one_raw(_email_query(email))

    async def get_raw_by_verified_email(self, email: str) -> dict[str, Any] | None:
        """The lookup identity matching must use: an unverified address names whoever typed it."""
        return await self.find_one_raw({**_email_query(email), "is_verified": True})

    async def find_raw_by_verified_emails(self, emails: list[str]) -> list[dict[str, Any]]:
        """Every verified account one of ``emails`` names, matched as ``get_raw_by_verified_email`` does."""
        patterns = [re.compile(f"^{re.escape(email)}$", re.IGNORECASE) for email in emails]
        cursor = self.collection.find({"email": {"$in": patterns}, "is_verified": True})
        return await cursor.to_list(None)

    async def usernames_by_id(self, user_ids: Iterable[str]) -> dict[str, str]:
        """Id -> username of every account among ``user_ids``, in one read; a deleted account is absent."""
        cursor = self.collection.find({"_id": {"$in": sorted(set(user_ids))}}, {"username": 1})
        return {doc["_id"]: doc["username"] async for doc in cursor}

    async def find_by_ids(self, user_ids: list[str]) -> list[dict[str, Any]]:
        cursor = self.collection.find({"_id": {"$in": user_ids}})
        return await cursor.to_list(None)

    async def exists_by_username(self, username: str) -> bool:
        return await self.exists({"username": username})

    async def exists_by_email(self, email: str) -> bool:
        return await self.exists(_email_query(email))
