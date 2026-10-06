"""Generic, type-safe base class for repositories."""

import logging
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel
from pymongo import ReplaceOne
from pymongo.errors import BulkWriteError


logger = logging.getLogger(__name__)

UpdateOps = dict[str, Any] | list[dict[str, Any]]

DUPLICATE_KEY_ERROR = 11000


async def find_window(
    collection: AsyncIOMotorCollection, query: dict[str, Any], limit: int, **find_kwargs: Any
) -> tuple[list[dict[str, Any]], int]:
    """The first ``limit`` matches and how many match in total.

    The count costs a round trip only once the read saturates, the only time the two can differ;
    a caller compares them to tell a truncated result from one that exactly fills the limit.
    """
    if limit <= 0:
        return [], await collection.count_documents(query)
    rows: list[dict[str, Any]] = await collection.find(query, limit=limit, **find_kwargs).to_list(length=limit)
    if len(rows) < limit:
        return rows, len(rows)
    return rows, await collection.count_documents(query)


def and_filters(*filters: dict[str, Any]) -> dict[str, Any]:
    """Every non-empty filter under ``$and``, as a key-by-key merge would let one ``$or`` or ``_id`` replace another."""
    present = [f for f in filters if f]
    if len(present) > 1:
        return {"$and": present}
    return dict(present[0]) if present else {}


class BaseRepository[T: BaseModel]:
    """Generic CRUD base. Subclasses set ``collection_name`` and ``model_class``."""

    collection_name: str
    model_class: type[T]

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection: AsyncIOMotorCollection = db[self.collection_name]

    def _to_model(self, data: dict[str, Any] | None) -> T | None:
        if data is None:
            return None
        return self.model_class(**data)

    def _to_model_list(self, docs: list[dict[str, Any]]) -> list[T]:
        return [self.model_class(**doc) for doc in docs]

    async def get_by_id(self, id: str) -> T | None:
        data = await self.collection.find_one({"_id": id})
        return self._to_model(data)

    async def get_raw_by_id(self, id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": id})

    async def find_one(self, query: dict[str, Any]) -> T | None:
        data = await self.collection.find_one(query)
        return self._to_model(data)

    async def find_one_raw(
        self,
        query: dict[str, Any],
        projection: dict[str, int] | None = None,
    ) -> dict[str, Any] | None:
        return await self.collection.find_one(query, projection)

    async def find_many(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str | None = None,
        sort_order: int = 1,
    ) -> list[T]:
        return self._to_model_list(await self.find_many_raw(query, skip, limit, sort_by, sort_order))

    async def find_many_raw(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str | None = None,
        sort_order: int = 1,
        projection: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        cursor = self.collection.find(query, projection)
        if sort_by:
            # Mongo leaves the order among equal keys open per query, so skip/limit pages would overlap.
            cursor = cursor.sort([(sort_by, sort_order)] if sort_by == "_id" else [(sort_by, sort_order), ("_id", 1)])
        cursor = cursor.skip(skip).limit(limit)
        return await cursor.to_list(limit)

    async def find_all_raw(
        self, query: dict[str, Any], projection: dict[str, int] | None = None
    ) -> list[dict[str, Any]]:
        """Every match, unbounded, for callers that fold the whole set."""
        return await self.collection.find(query, projection).to_list(None)

    async def count(self, query: dict[str, Any] | None = None) -> int:
        return await self.collection.count_documents(query or {})

    async def exists(self, query: dict[str, Any]) -> bool:
        return await self.collection.find_one(query, {"_id": 1}) is not None

    async def create(self, model: T) -> T:
        await self.collection.insert_one(model.model_dump(by_alias=True))
        return model

    async def create_raw(self, data: dict[str, Any]) -> None:
        await self.collection.insert_one(data)

    async def replace_many_raw(self, docs: list[dict[str, Any]], fresh: bool = False) -> int:
        """Upsert each document whole by ``_id``; ordered=False so one failed write doesn't abort the batch.

        ``fresh`` (none of them stored yet) inserts instead, at half an upsert's cost, and replaces the
        documents an ``_id`` collision refused, such as those a concurrent run wrote first.
        """
        if not docs:
            return 0
        try:
            if fresh:
                await self.collection.insert_many(docs, ordered=False)
                return len(docs)
            result = await self.collection.bulk_write(
                [ReplaceOne({"_id": doc["_id"]}, doc, upsert=True) for doc in docs], ordered=False
            )
            return result.upserted_count + result.matched_count
        except BulkWriteError as e:
            if e.details.get("writeConcernErrors"):
                raise
            errors = e.details["writeErrors"]
            stored = {error["index"] for error in errors if fresh and error["code"] == DUPLICATE_KEY_ERROR}
            dropped = [error for error in errors if error["index"] not in stored]
            if dropped:
                logger.warning(
                    "Bulk replace into %s dropped %d of %d docs (first error: %s)",
                    self.collection_name,
                    len(dropped),
                    len(docs),
                    (dropped[0].get("errmsg", "") or "")[:200],
                )
            written: int = e.details.get("nInserted", 0) + e.details.get("nUpserted", 0) + e.details.get("nMatched", 0)
            return written + await self.replace_many_raw([docs[index] for index in sorted(stored)])

    async def update(self, id: str, update_data: dict[str, Any]) -> T | None:
        if update_data:
            await self.collection.update_one({"_id": id}, {"$set": update_data})
        return await self.get_by_id(id)

    async def update_raw(self, id: str, update_ops: UpdateOps, guard: dict[str, Any] | None = None) -> bool:
        """``update_ops`` reaches the server verbatim: modifiers as a document, a pipeline as a list.

        ``guard`` joins the write's own filter so a condition established beforehand cannot go
        stale in between. False when it no longer held.
        """
        result = await self.collection.update_one({"_id": id, **(guard or {})}, update_ops)
        return bool(result.matched_count)

    async def update_many(self, query: dict[str, Any], update_data: dict[str, Any]) -> int:
        result = await self.collection.update_many(query, {"$set": update_data})
        return result.modified_count

    async def upsert(self, query: dict[str, Any], data: dict[str, Any]) -> None:
        await self.collection.update_one(query, {"$set": data}, upsert=True)

    async def delete(self, id: str) -> bool:
        result = await self.collection.delete_one({"_id": id})
        return result.deleted_count > 0

    async def delete_many(self, query: dict[str, Any]) -> int:
        result = await self.collection.delete_many(query)
        return result.deleted_count

    async def delete_older_writes(self, query: dict[str, Any], written_at: datetime) -> None:
        """Delete the matches no write since ``written_at`` has touched, undated rows included."""
        await self.delete_many({**query, "$nor": [{"created_at": {"$gte": written_at}}]})

    async def aggregate(
        self,
        pipeline: list[dict[str, Any]],
        limit: int | None = None,
        allow_disk_use: bool = False,
        hint: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        """allow_disk_use lets mongod spill large $group/$sort sets to disk past the 100MB limit."""
        options: dict[str, Any] = {}
        if allow_disk_use:
            options["allowDiskUse"] = True
        if hint:
            options["hint"] = hint
        return await self.collection.aggregate(pipeline, **options).to_list(limit)

    async def iterate(self, query: dict[str, Any] | None = None) -> AsyncGenerator[T, None]:
        async for doc in self.collection.find(query or {}):
            yield self.model_class(**doc)

    async def iterate_raw(
        self,
        query: dict[str, Any] | None = None,
        projection: dict[str, int] | None = None,
        sort: list[tuple[str, int]] | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        cursor = self.collection.find(query or {}, projection)
        if sort:
            cursor = cursor.sort(sort)
        async for doc in cursor:
            yield doc
