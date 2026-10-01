"""Distributed locks for multi-pod coordination (e.g. Slack token refresh)."""

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable, Coroutine
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.core.constants import INSTANCE_ID

logger = logging.getLogger(__name__)

LOCK_RENEWALS_PER_TTL = 3


class LockLost(Exception):
    """Another holder took the lock over while its work was still running."""


def new_lock_holder() -> str:
    """A holder unique to one acquisition, so a release never drops a lock someone took over."""
    return f"{INSTANCE_ID}:{uuid.uuid4().hex[:12]}"


async def run_holding_lock[T](
    renew: Callable[[], Awaitable[bool]], ttl_seconds: float, work: Coroutine[Any, Any, T]
) -> T:
    """Run ``work`` while renewing its lock; cancel it and raise LockLost once another holder took the lock over."""
    task = asyncio.create_task(work)

    async def heartbeat() -> None:
        lost = False
        while True:
            await asyncio.sleep(ttl_seconds / LOCK_RENEWALS_PER_TTL)
            try:
                lost = lost or not await renew()
            except PyMongoError as e:
                logger.warning("Lock renewal failed, retrying: %s", e)
            if lost:
                # Each tick again: a cleanup that raises while cancelled swallows the cancellation.
                task.cancel()

    beat = asyncio.create_task(heartbeat())
    try:
        return await task
    except asyncio.CancelledError:
        # Only the heartbeat cancels the work without cancelling us; our own cancellation must propagate.
        this_task = asyncio.current_task()
        if this_task is None or this_task.cancelling():
            raise
        raise LockLost from None
    finally:
        beat.cancel()
        await asyncio.gather(beat, return_exceptions=True)


class DistributedLocksRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.distributed_locks

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

    async def renew_lock(self, lock_name: str, holder_id: str, ttl_seconds: int = 30) -> bool:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        # False once another holder took the expired lock over (or it was released): the caller lost it.
        result = await self.collection.update_one(
            {"_id": lock_name, "holder": holder_id},
            {"$set": {"expires_at": expires_at}},
        )
        return result.matched_count > 0

    async def release_lock(self, lock_name: str, holder_id: str) -> bool:
        # Scope delete to holder so a pod can't delete a lock another pod took over after TTL.
        result = await self.collection.delete_one({"_id": lock_name, "holder": holder_id})
        return result.deleted_count > 0

    async def held_locks(self, lock_names: list[str]) -> set[str]:
        now = datetime.now(timezone.utc)
        cursor = self.collection.find({"_id": {"$in": lock_names}, "expires_at": {"$gt": now}}, {"_id": 1})
        return {lock["_id"] async for lock in cursor}
