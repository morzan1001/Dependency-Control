"""release_lock must be holder-scoped: only the holder that owns a lock may release it."""

import asyncio


from app.repositories.distributed_locks import DistributedLocksRepository


class _InMemoryLockCollection:
    """Minimal async MongoDB-like collection for distributed_locks documents."""

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
                if "$exists" in cond:
                    exists = key in doc
                    if exists != cond["$exists"]:
                        return False
                if "$lt" in cond:
                    if not (key in doc and doc[key] < cond["$lt"]):
                        return False
                if "$gt" in cond:
                    if not (key in doc and doc[key] > cond["$gt"]):
                        return False
            else:
                if doc.get(key) != cond:
                    return False
        return True

    async def find_one_and_update(self, filter, update, upsert=False, return_document=True):
        for doc in self.docs.values():
            if doc["_id"] == filter["_id"] and self._matches(doc, filter):
                doc.update(update.get("$set", {}))
                return dict(doc)
        if upsert:
            # Present-but-non-matching _id => duplicate-key in real Mongo => no upsert.
            if filter["_id"] in self.docs:
                return None
            new_doc = {"_id": filter["_id"]}
            new_doc.update(update.get("$set", {}))
            self.docs[filter["_id"]] = new_doc
            return dict(new_doc)
        return None

    async def delete_one(self, filter):
        deleted = 0
        for _id, doc in list(self.docs.items()):
            if doc["_id"] == filter.get("_id") and self._matches(doc, filter):
                del self.docs[_id]
                deleted = 1
                break

        class _Result:
            deleted_count = deleted

        return _Result()


class _FakeDB:
    def __init__(self, collection):
        self.distributed_locks = collection


def _make_repo():
    coll = _InMemoryLockCollection()
    db = _FakeDB(coll)
    return DistributedLocksRepository(db), coll


class TestHolderScopedRelease:
    def test_non_holder_cannot_release_anothers_lock(self):
        async def scenario():
            repo, _ = _make_repo()

            assert await repo.acquire_lock("lock-x", "A", ttl_seconds=300) is True

            # A different pod must not be able to release A's lock.
            released = await repo.release_lock("lock-x", "B")
            assert released is False

            acquired_by_c = await repo.acquire_lock("lock-x", "C", ttl_seconds=300)
            assert acquired_by_c is False

        asyncio.run(scenario())

    def test_holder_can_release_own_lock(self):
        async def scenario():
            repo, _ = _make_repo()

            assert await repo.acquire_lock("lock-y", "A", ttl_seconds=300) is True

            released = await repo.release_lock("lock-y", "A")
            assert released is True

            acquired_by_b = await repo.acquire_lock("lock-y", "B", ttl_seconds=300)
            assert acquired_by_b is True

        asyncio.run(scenario())
