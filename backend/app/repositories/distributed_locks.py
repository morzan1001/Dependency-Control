"""
Distributed Locks Repository

Manages distributed locks for multi-pod coordination.
Used for preventing race conditions across pods (e.g., Slack token refresh).
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase


class DistributedLocksRepository:
    """Repository for distributed lock operations across multiple pods."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.distributed_locks

    async def acquire_lock(self, lock_name: str, holder_id: str, ttl_seconds: int = 30) -> bool:
        """
        Try to acquire a distributed lock atomically.

        Args:
            lock_name: Name of the lock
            holder_id: Identifier of the pod/process acquiring the lock
            ttl_seconds: Lock TTL in seconds (auto-expires if holder crashes)

        Returns:
            True if lock acquired successfully, False if lock is held by another process
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Atomic operation: Try to acquire lock
        result = await self.collection.find_one_and_update(
            {
                "_id": lock_name,
                # Lock is available if:
                # 1. It doesn't exist, OR
                # 2. It has expired
                "$or": [
                    {"expires_at": {"$exists": False}},
                    {"expires_at": {"$lt": now}},
                ],
            },
            {
                "$set": {
                    "acquired_at": now,
                    "expires_at": expires_at,
                    "holder": holder_id,
                }
            },
            upsert=True,
            return_document=True,
        )

        return result is not None

    async def release_lock(self, lock_name: str) -> bool:
        """
        Release a distributed lock.

        Args:
            lock_name: Name of the lock to release

        Returns:
            True if lock was released, False if lock didn't exist
        """
        result = await self.collection.delete_one({"_id": lock_name})
        return result.deleted_count > 0

    async def get_lock_info(self, lock_name: str) -> Optional[dict]:
        """
        Get information about a lock.

        Args:
            lock_name: Name of the lock

        Returns:
            Lock document or None if not found
        """
        return await self.collection.find_one({"_id": lock_name})

    async def is_locked(self, lock_name: str) -> bool:
        """
        Check if a lock is currently held.

        Args:
            lock_name: Name of the lock

        Returns:
            True if lock is held and not expired, False otherwise
        """
        now = datetime.now(timezone.utc)
        lock = await self.collection.find_one({"_id": lock_name, "expires_at": {"$gt": now}})
        return lock is not None

    async def cleanup_expired_locks(self) -> int:
        """
        Remove expired locks from the database.

        This is a maintenance operation that can be run periodically.

        Returns:
            Number of expired locks removed
        """
        now = datetime.now(timezone.utc)
        result = await self.collection.delete_many({"expires_at": {"$lt": now}})
        return result.deleted_count
