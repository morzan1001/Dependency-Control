"""acquire_lock must return False (not raise) when the lock is already held.

Regression for Finding 1 — the upsert filter matches nothing when a lock doc
exists and is unexpired, so real MongoDB attempts an INSERT with the same _id
and raises DuplicateKeyError (E11000). Previously that exception propagated to
callers (stats recalculation, archive housekeeping, Slack refresh) which all
expect a boolean contract. The repository must translate the duplicate-key into
a graceful False.

The in-memory collection here mirrors real MongoDB semantics: an upsert whose
filter fails to match a present-but-unexpired document raises DuplicateKeyError,
exactly as the server does.
"""

import asyncio

from pymongo.errors import DuplicateKeyError

from app.repositories.distributed_locks import DistributedLocksRepository


class _MongoLikeLockCollection:
    """Async collection that raises DuplicateKeyError on a conflicting upsert,
    faithfully reproducing real MongoDB E11000 behavior."""

    def __init__(self):
        self.docs = {}  # _id -> document

    def with_options(self, **_kwargs):
        return self

    def _matches(self, doc, query):
        for key, cond in query.items():
            if key == "$or":
                if not any(self._matches(doc, sub) for sub in cond):
                    return False
                continue
            if isinstance(cond, dict):
                if "$exists" in cond and (key in doc) != cond["$exists"]:
                    return False
                if "$lt" in cond and not (key in doc and doc[key] < cond["$lt"]):
                    return False
                if "$gt" in cond and not (key in doc and doc[key] > cond["$gt"]):
                    return False
            elif doc.get(key) != cond:
                return False
        return True

    async def find_one_and_update(self, filter, update, upsert=False, return_document=True):
        for doc in self.docs.values():
            if doc["_id"] == filter["_id"] and self._matches(doc, filter):
                doc.update(update.get("$set", {}))
                return dict(doc)
        # No matching existing doc.
        if upsert:
            if filter["_id"] in self.docs:
                # A doc with this _id exists but did not match the filter:
                # the upsert insert collides on the unique _id -> E11000.
                raise DuplicateKeyError("E11000 duplicate key error: _id")
            new_doc = {"_id": filter["_id"]}
            new_doc.update(update.get("$set", {}))
            self.docs[filter["_id"]] = new_doc
            return dict(new_doc)
        return None


class _FakeDB:
    def __init__(self, collection):
        self.distributed_locks = collection


def _make_repo():
    coll = _MongoLikeLockCollection()
    return DistributedLocksRepository(_FakeDB(coll)), coll


class TestAcquireLockWhenHeld:
    def test_returns_false_instead_of_raising_when_lock_held(self):
        async def scenario():
            repo, _ = _make_repo()

            # A acquires the lock.
            assert await repo.acquire_lock("lock-a", "A", ttl_seconds=300) is True

            # B contends for the same held lock: must get a graceful False,
            # NOT a propagating DuplicateKeyError.
            assert await repo.acquire_lock("lock-a", "B", ttl_seconds=300) is False

        asyncio.run(scenario())

    def test_expired_lock_can_be_taken_over(self):
        async def scenario():
            repo, coll = _make_repo()

            assert await repo.acquire_lock("lock-b", "A", ttl_seconds=300) is True

            # Force the existing lock to be expired.
            from datetime import datetime, timezone

            coll.docs["lock-b"]["expires_at"] = datetime(2000, 1, 1, tzinfo=timezone.utc)

            # A different pod can take over the expired lock.
            assert await repo.acquire_lock("lock-b", "B", ttl_seconds=300) is True

        asyncio.run(scenario())
