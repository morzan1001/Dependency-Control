"""renew_lock extends only the caller's own lock, so a holder learns when another one took its expired lock over."""

from datetime import datetime, timedelta, timezone

import pytest

from app.repositories.distributed_locks import DistributedLocksRepository
from tests.mocks.fake_mongo import FakeDatabase


def _as_utc(moment: datetime) -> datetime:
    """The fake store hands datetimes back naive, as MongoDB does."""
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_renew_extends_the_holders_lock():
    db = FakeDatabase()
    repo = DistributedLocksRepository(db)
    assert await repo.acquire_lock("lock-x", "pod-a", ttl_seconds=30)

    assert await repo.renew_lock("lock-x", "pod-a", ttl_seconds=600) is True

    lock = await db.distributed_locks.find_one({"_id": "lock-x"})
    assert _as_utc(lock["expires_at"]) > datetime.now(timezone.utc) + timedelta(seconds=500)
    assert lock["holder"] == "pod-a"


@pytest.mark.asyncio
async def test_renew_refuses_a_lock_another_holder_took_over():
    db = FakeDatabase()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)
    await db.distributed_locks.insert_one({"_id": "lock-x", "holder": "pod-b", "expires_at": expires_at})

    assert await DistributedLocksRepository(db).renew_lock("lock-x", "pod-a", ttl_seconds=600) is False

    lock = await db.distributed_locks.find_one({"_id": "lock-x"})
    assert lock["holder"] == "pod-b"
    assert _as_utc(lock["expires_at"]) < datetime.now(timezone.utc) + timedelta(seconds=60)


@pytest.mark.asyncio
async def test_renew_refuses_a_released_lock():
    db = FakeDatabase()

    assert await DistributedLocksRepository(db).renew_lock("lock-x", "pod-a", ttl_seconds=600) is False

    assert await db.distributed_locks.find_one({"_id": "lock-x"}) is None
