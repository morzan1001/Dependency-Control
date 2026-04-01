"""
Base Repository Pattern

Provides a generic, type-safe base class for all repositories.
Reduces code duplication and ensures consistent database operations.
"""

from typing import Any, AsyncGenerator, Dict, List, Optional, Type

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel

from app.core.metrics import track_db_operation


class BaseRepository[T: BaseModel]:
    """
    Generic base repository providing common CRUD operations.

    Type Parameters:
        T: The Pydantic model class this repository manages

    Usage:
        class UserRepository(BaseRepository[User]):
            collection_name = "users"
            model_class = User
    """

    # Subclasses must define these
    collection_name: str
    model_class: Type[T]

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection: AsyncIOMotorCollection = db[self.collection_name]

    def _to_model(self, data: Optional[Dict[str, Any]]) -> Optional[T]:
        """Convert a raw document to a model instance."""
        if data is None:
            return None
        return self.model_class(**data)

    def _to_model_list(self, docs: List[Dict[str, Any]]) -> List[T]:
        """Convert a list of raw documents to model instances."""
        return [self.model_class(**doc) for doc in docs]

    async def get_by_id(self, id: str) -> Optional[T]:
        """Get a document by ID and return as model instance."""
        with track_db_operation(self.collection_name, "find_one"):
            data = await self.collection.find_one({"_id": id})
        return self._to_model(data)

    async def get_raw_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        """Get a raw document by ID."""
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one({"_id": id})

    async def find_one(
        self,
        query: Dict[str, Any],
        projection: Optional[Dict[str, int]] = None,
    ) -> Optional[T]:
        """Find one document matching query and return as model instance."""
        with track_db_operation(self.collection_name, "find_one"):
            data = await self.collection.find_one(query, projection)
        return self._to_model(data)

    async def find_one_raw(
        self,
        query: Dict[str, Any],
        projection: Optional[Dict[str, int]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Find one raw document matching query."""
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one(query, projection)

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: Optional[str] = None,
        sort_order: int = 1,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[T]:
        """Find multiple documents and return as model instances."""
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query, projection)
            if sort_by:
                cursor = cursor.sort(sort_by, sort_order)
            cursor = cursor.skip(skip).limit(limit)
            docs = await cursor.to_list(limit)
        return self._to_model_list(docs)

    async def find_many_raw(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: Optional[str] = None,
        sort_order: int = 1,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        """Find multiple raw documents."""
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query, projection)
            if sort_by:
                cursor = cursor.sort(sort_by, sort_order)
            cursor = cursor.skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count documents matching query."""
        with track_db_operation(self.collection_name, "count"):
            return await self.collection.count_documents(query or {})

    async def exists(self, query: Dict[str, Any]) -> bool:
        """Check if a document matching the query exists."""
        with track_db_operation(self.collection_name, "find_one"):
            return await self.collection.find_one(query, {"_id": 1}) is not None

    async def create(self, model: T) -> T:
        """Create a new document from a model instance."""
        with track_db_operation(self.collection_name, "insert_one"):
            await self.collection.insert_one(model.model_dump(by_alias=True))
        return model

    async def create_raw(self, data: Dict[str, Any]) -> None:
        """Create a new document from raw data."""
        with track_db_operation(self.collection_name, "insert_one"):
            await self.collection.insert_one(data)

    async def create_many(self, models: List[T]) -> int:
        """Create multiple documents from model instances."""
        if not models:
            return 0
        docs = [m.model_dump(by_alias=True) for m in models]
        with track_db_operation(self.collection_name, "insert_many"):
            result = await self.collection.insert_many(docs)
        return len(result.inserted_ids)

    async def create_many_raw(self, docs: List[Dict[str, Any]]) -> int:
        """
        Create multiple documents from raw data.
        Uses ordered=False to continue inserting even if some documents are duplicates.
        """
        if not docs:
            return 0
        with track_db_operation(self.collection_name, "insert_many"):
            try:
                result = await self.collection.insert_many(docs, ordered=False)
                return len(result.inserted_ids)
            except Exception as e:
                # Handle BulkWriteError - some documents may have been inserted
                if hasattr(e, "details") and "writeErrors" in e.details:
                    # Count successful inserts
                    inserted_count: int = e.details.get("nInserted", 0)
                    return inserted_count
                raise

    async def update(self, id: str, update_data: Dict[str, Any]) -> Optional[T]:
        """Update a document by ID and return the updated model."""
        if update_data:
            with track_db_operation(self.collection_name, "update_one"):
                await self.collection.update_one({"_id": id}, {"$set": update_data})
        return await self.get_by_id(id)

    async def update_raw(self, id: str, update_ops: Dict[str, Any]) -> None:
        """Update a document with raw MongoDB operations (e.g., $set, $push)."""
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one({"_id": id}, update_ops)

    async def update_many(self, query: Dict[str, Any], update_data: Dict[str, Any]) -> int:
        """Update multiple documents matching query."""
        with track_db_operation(self.collection_name, "update_many"):
            result = await self.collection.update_many(query, {"$set": update_data})
        return result.modified_count

    async def upsert(self, query: Dict[str, Any], data: Dict[str, Any]) -> None:
        """Update or insert a document."""
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one(query, {"$set": data}, upsert=True)

    async def delete(self, id: str) -> bool:
        """Delete a document by ID."""
        with track_db_operation(self.collection_name, "delete_one"):
            result = await self.collection.delete_one({"_id": id})
        return result.deleted_count > 0

    async def delete_many(self, query: Dict[str, Any]) -> int:
        """Delete multiple documents matching query."""
        with track_db_operation(self.collection_name, "delete_many"):
            result = await self.collection.delete_many(query)
        return result.deleted_count

    async def aggregate(self, pipeline: List[Dict[str, Any]], limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run an aggregation pipeline.

        Args:
            pipeline: MongoDB aggregation pipeline stages.
            limit: Maximum number of results. Use $limit in the pipeline for best performance.
        """
        with track_db_operation(self.collection_name, "aggregate"):
            return await self.collection.aggregate(pipeline).to_list(limit)

    async def iterate(
        self,
        query: Optional[Dict[str, Any]] = None,
        projection: Optional[Dict[str, int]] = None,
    ) -> AsyncGenerator[Optional[T], None]:
        """Iterate over documents matching query (async generator)."""
        async for doc in self.collection.find(query or {}, projection):
            yield self._to_model(doc)

    async def iterate_raw(
        self,
        query: Optional[Dict[str, Any]] = None,
        projection: Optional[Dict[str, int]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Iterate over raw documents matching query (async generator)."""
        async for doc in self.collection.find(query or {}, projection):
            yield doc
