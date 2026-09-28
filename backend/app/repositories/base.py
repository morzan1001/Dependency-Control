"""Generic, type-safe base class for repositories."""

import logging
from collections.abc import AsyncGenerator
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel
from pymongo.errors import BulkWriteError


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
        if limit <= 0:
            return []
        cursor = self.collection.find(query)
        if sort_by:
            cursor = cursor.sort(sort_by, sort_order)
        cursor = cursor.skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
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
        if limit <= 0:
            return []
        cursor = self.collection.find(query, projection)
        if sort_by:
            cursor = cursor.sort(sort_by, sort_order)
        cursor = cursor.skip(skip).limit(limit)
        return await cursor.to_list(limit)

    async def count(self, query: dict[str, Any] | None = None) -> int:
        return await self.collection.count_documents(query or {})

    async def exists(self, query: dict[str, Any]) -> bool:
        return await self.collection.find_one(query, {"_id": 1}) is not None

    async def create(self, model: T) -> T:
        await self.collection.insert_one(model.model_dump(by_alias=True))
        return model

    async def create_raw(self, data: dict[str, Any]) -> None:
        await self.collection.insert_one(data)

    async def create_many_raw(self, docs: list[dict[str, Any]]) -> int:
        """ordered=False so a duplicate-key error doesn't abort the batch."""
        if not docs:
            return 0
        try:
            result = await self.collection.insert_many(docs, ordered=False)
            return len(result.inserted_ids)
        except BulkWriteError as e:
            if e.details.get("writeConcernErrors"):
                raise
            write_errors = e.details["writeErrors"]
            logger.warning(
                "Bulk insert into %s dropped %d of %d docs (first error: %s)",
                self.collection_name,
                len(write_errors),
                len(docs),
                (write_errors[0].get("errmsg", "") or "")[:200] if write_errors else "",
            )
            inserted_count: int = e.details.get("nInserted", 0)
            return inserted_count

    async def update(self, id: str, update_data: dict[str, Any]) -> T | None:
        if update_data:
            await self.collection.update_one({"_id": id}, {"$set": update_data})
        return await self.get_by_id(id)

    async def update_raw(self, id: str, update_ops: dict[str, Any]) -> None:
        await self.collection.update_one({"_id": id}, update_ops)

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

    async def aggregate(
        self,
        pipeline: list[dict[str, Any]],
        limit: int | None = None,
        allow_disk_use: bool = False,
    ) -> list[dict[str, Any]]:
        """allow_disk_use lets mongod spill large $group/$sort sets to disk past the 100MB limit."""
        cursor = (
            self.collection.aggregate(pipeline, allowDiskUse=True)
            if allow_disk_use
            else self.collection.aggregate(pipeline)
        )
        return await cursor.to_list(limit)

    async def iterate(self, query: dict[str, Any] | None = None) -> AsyncGenerator[T, None]:
        async for doc in self.collection.find(query or {}):
            yield self.model_class(**doc)

    async def iterate_raw(
        self,
        query: dict[str, Any] | None = None,
        projection: dict[str, int] | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        async for doc in self.collection.find(query or {}, projection):
            yield doc
