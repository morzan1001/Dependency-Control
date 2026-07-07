"""Blacklisted JWT tokens for logout. A MongoDB TTL index removes expired entries."""

from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReadPreference


class TokenBlacklistRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.token_blacklist

    async def blacklist_token(self, jti: str, expires_at: datetime, reason: str = "logout") -> bool:
        """Returns False if the token is already blacklisted."""
        try:
            await self.collection.insert_one(
                {
                    "_id": jti,  # jti as _id enforces dedup
                    "jti": jti,
                    "blacklisted_at": datetime.now(),
                    "expires_at": expires_at,
                    "reason": reason,
                }
            )
            return True
        except Exception:
            # Token already blacklisted (duplicate key error)
            return False

    async def is_blacklisted(self, jti: str) -> bool:
        # A just-revoked token must not slip through on a stale Secondary.
        primary = self.collection.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
        result = await primary.find_one({"_id": jti})
        return result is not None
