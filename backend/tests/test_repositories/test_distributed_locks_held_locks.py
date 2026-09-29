"""held_locks reports which of the named locks are held: only unexpired locks count."""

import asyncio
from datetime import datetime, timedelta, timezone

from app.repositories.distributed_locks import DistributedLocksRepository
from tests.mocks.fake_mongo import FakeDatabase


def test_held_locks_reports_only_unexpired_locks():
    now = datetime.now(timezone.utc)
    db = FakeDatabase()

    async def run() -> set[str]:
        await db.distributed_locks.insert_many(
            [
                {"_id": "lock-held", "holder": "pod-a", "expires_at": now + timedelta(minutes=5)},
                {"_id": "lock-expired", "holder": "pod-b", "expires_at": now - timedelta(minutes=5)},
                {"_id": "lock-other", "holder": "pod-c", "expires_at": now + timedelta(minutes=5)},
            ]
        )
        return await DistributedLocksRepository(db).held_locks(["lock-held", "lock-expired", "lock-absent"])

    assert asyncio.run(run()) == {"lock-held"}
