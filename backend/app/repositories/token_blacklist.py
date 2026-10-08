"""Spent refresh-token JTIs, so a rotated refresh token is refused; a TTL index removes expired entries."""

from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError


class TokenBlacklistRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.token_blacklist

    async def blacklist_token(self, jti: str, expires_at: datetime) -> bool:
        """Returns False if the token is already blacklisted."""
        try:
            await self.collection.insert_one(
                {
                    "_id": jti,  # jti as _id enforces dedup
                    "jti": jti,
                    "blacklisted_at": datetime.now(timezone.utc),
                    "expires_at": expires_at,
                }
            )
            return True
        except DuplicateKeyError:
            return False

    async def is_blacklisted(self, jti: str) -> bool:
        result = await self.collection.find_one({"_id": jti})
        return result is not None
