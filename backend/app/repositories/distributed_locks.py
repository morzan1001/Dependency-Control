"""Distributed locks for multi-pod coordination (e.g. Slack token refresh)."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReadPreference
from pymongo.errors import DuplicateKeyError


class DistributedLocksRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.distributed_locks
        # Lock-state reads must be coherent — two pods must never both see "free".
        self._reads = self.collection.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]

    async def acquire_lock(self, lock_name: str, holder_id: str, ttl_seconds: int = 30) -> bool:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        # A held/unexpired lock makes the filter match nothing, so the upsert hits a
        # duplicate _id (E11000); that just means someone else holds it, so return False.
        try:
            result = await self.collection.find_one_and_update(
                {
                    "_id": lock_name,
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
        except DuplicateKeyError:
            return False

        return result is not None

    async def release_lock(self, lock_name: str, holder_id: str) -> bool:
        # Scope delete to holder so a pod can't delete a lock another pod took over after TTL.
        result = await self.collection.delete_one({"_id": lock_name, "holder": holder_id})
        return result.deleted_count > 0

    async def get_lock_info(self, lock_name: str) -> Optional[dict]:
        return await self._reads.find_one({"_id": lock_name})

    async def is_locked(self, lock_name: str) -> bool:
        now = datetime.now(timezone.utc)
        lock = await self._reads.find_one({"_id": lock_name, "expires_at": {"$gt": now}})
        return lock is not None

    async def cleanup_expired_locks(self) -> int:
        now = datetime.now(timezone.utc)
        result = await self.collection.delete_many({"expires_at": {"$lt": now}})
        return result.deleted_count
