"""Generic, type-safe base class for repositories."""

import logging
from collections.abc import AsyncGenerator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel

from app.core.metrics import track_db_operation

logger = logging.getLogger(__name__)


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
        with track_db_operation(self.collection_name, "find_one"):
            data = await self.collection.find_one({"_id": id})
        return self._to_model(data)

    async def get_raw_by_id(self, id: str) -> dict[str, Any] | None:
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"_id": id})

    async def find_one(self, query: dict[str, Any]) -> T | None:
        with track_db_operation(self.collection_name, "find_one"):
            data = await self.collection.find_one(query)
        return self._to_model(data)

    async def find_one_raw(
        self,
        query: dict[str, Any],
        projection: dict[str, int] | None = None,
    ) -> dict[str, Any] | None:
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one(query, projection)

    async def find_many(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str | None = None,
        sort_order: int = 1,
    ) -> list[T]:
        # pymongo .limit(0) means unbounded; floor to 1 to avoid loading the whole collection.
        safe_limit = max(limit, 1)
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query)
            if sort_by:
                cursor = cursor.sort(sort_by, sort_order)
            cursor = cursor.skip(skip).limit(safe_limit)
            docs = await cursor.to_list(safe_limit)
        return self._to_model_list(docs)

    async def find_many_raw(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str | None = None,
        sort_order: int = 1,
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query, projection)
            if sort_by:
                cursor = cursor.sort(sort_by, sort_order)
            cursor = cursor.skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def count(self, query: dict[str, Any] | None = None) -> int:
        with track_db_operation(self.collection_name, "count"):
            return await self.collection.count_documents(query or {})

    async def exists(self, query: dict[str, Any]) -> bool:
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one(query, {"_id": 1}) is not None

    async def create(self, model: T) -> T:
        with track_db_operation(self.collection_name, "insert_one"):
            await self.collection.insert_one(model.model_dump(by_alias=True))
        return model

    async def create_raw(self, data: dict[str, Any]) -> None:
        with track_db_operation(self.collection_name, "insert_one"):
            await self.collection.insert_one(data)

    async def create_many(self, models: list[T]) -> int:
        if not models:
            return 0
        docs = [m.model_dump(by_alias=True) for m in models]
        with track_db_operation(self.collection_name, "insert_many"):
            result = await self.collection.insert_many(docs)
        return len(result.inserted_ids)

    async def create_many_raw(self, docs: list[dict[str, Any]]) -> int:
        """ordered=False so a duplicate-key error doesn't abort the batch."""
        if not docs:
            return 0
        with track_db_operation(self.collection_name, "insert_many"):
            try:
                result = await self.collection.insert_many(docs, ordered=False)
                return len(result.inserted_ids)
            except Exception as e:
                # BulkWriteError can still report partial success.
                if hasattr(e, "details") and "writeErrors" in e.details:
                    write_errors = e.details["writeErrors"]
                    inserted_count: int = e.details.get("nInserted", 0)
                    logger.warning(
                        "Bulk insert into %s dropped %d of %d docs (first error: %s)",
                        self.collection_name,
                        len(write_errors),
                        len(docs),
                        (write_errors[0].get("errmsg", "") or "")[:200] if write_errors else "",
                    )
                    return inserted_count
                raise

    async def update(self, id: str, update_data: dict[str, Any]) -> T | None:
        if update_data:
            with track_db_operation(self.collection_name, "update_one"):
                await self.collection.update_one({"_id": id}, {"$set": update_data})
        return await self.get_by_id(id)

    async def update_raw(self, id: str, update_ops: dict[str, Any]) -> None:
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one({"_id": id}, update_ops)

    async def update_many(self, query: dict[str, Any], update_data: dict[str, Any]) -> int:
        with track_db_operation(self.collection_name, "update_many"):
            result = await self.collection.update_many(query, {"$set": update_data})
        return result.modified_count

    async def upsert(self, query: dict[str, Any], data: dict[str, Any]) -> None:
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one(query, {"$set": data}, upsert=True)

    async def delete(self, id: str) -> bool:
        with track_db_operation(self.collection_name, "delete_one"):
            result = await self.collection.delete_one({"_id": id})
        return result.deleted_count > 0

    async def delete_many(self, query: dict[str, Any]) -> int:
        with track_db_operation(self.collection_name, "delete_many"):
            result = await self.collection.delete_many(query)
        return result.deleted_count

    async def aggregate(
        self,
        pipeline: list[dict[str, Any]],
        limit: int | None = None,
        allow_disk_use: bool = False,
    ) -> list[dict[str, Any]]:
        """allow_disk_use lets mongod spill large $group/$sort sets to disk past the 100MB limit."""
        with track_db_operation(self.collection_name, "aggregate"):
            cursor = (
                self.collection.aggregate(pipeline, allowDiskUse=True)
                if allow_disk_use
                else self.collection.aggregate(pipeline)
            )
            return await cursor.to_list(limit)

    async def iterate(self, query: dict[str, Any] | None = None) -> AsyncGenerator[T | None, None]:
        async for doc in self.collection.find(query or {}):
            yield self._to_model(doc)

    async def iterate_raw(
        self,
        query: dict[str, Any] | None = None,
        projection: dict[str, int] | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        async for doc in self.collection.find(query or {}, projection):
            yield doc
