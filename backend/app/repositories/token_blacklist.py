"""
Token Blacklist Repository

Manages blacklisted JWT tokens for logout functionality.
Tokens are automatically removed after expiration via MongoDB TTL index.
"""

from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorDatabase


class TokenBlacklistRepository:
    """Repository for token blacklist operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.token_blacklist

    async def blacklist_token(
        self, jti: str, expires_at: datetime, reason: str = "logout"
    ) -> bool:
        """
        Add a token to the blacklist.

        Args:
            jti: JWT ID (jti claim from token)
            expires_at: Token expiration datetime
            reason: Reason for blacklisting (logout, password_change, etc.)

        Returns:
            True if token was blacklisted, False if already blacklisted
        """
        try:
            await self.collection.insert_one(
                {
                    "_id": jti,  # Use jti as primary key for uniqueness
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
        """
        Check if a token is blacklisted.

        Args:
            jti: JWT ID to check

        Returns:
            True if token is blacklisted, False otherwise
        """
        result = await self.collection.find_one({"_id": jti})
        return result is not None

    async def remove_from_blacklist(self, jti: str) -> bool:
        """
        Remove a token from blacklist (rarely needed).

        Args:
            jti: JWT ID to remove

        Returns:
            True if token was removed, False if wasn't blacklisted
        """
        result = await self.collection.delete_one({"_id": jti})
        return result.deleted_count > 0

    async def cleanup_expired(self) -> int:
        """
        Manually cleanup expired tokens (TTL index does this automatically).

        Returns:
            Number of tokens removed
        """
        now = datetime.now()
        result = await self.collection.delete_many({"expires_at": {"$lt": now}})
        return result.deleted_count
