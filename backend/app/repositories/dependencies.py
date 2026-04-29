"""Repository for dependencies."""

from typing import Any, Dict, List, Optional

from app.models.dependency import Dependency
from app.repositories.base import BaseRepository


class DependencyRepository(BaseRepository[Dependency]):
    collection_name = "dependencies"
    model_class = Dependency

    async def get_by_name(self, name: str) -> Optional[Dependency]:
        return await self.find_one({"name": name})

    async def find_by_scan(
        self,
        scan_id: str,
        skip: int = 0,
        limit: int = 10000,
    ) -> List[Dependency]:
        return await self.find_many({"scan_id": scan_id}, skip=skip, limit=limit)

    async def find_all(
        self,
        query: Optional[Dict[str, Any]] = None,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        """Returns raw dicts. Use iterate() for large result sets to avoid loading
        everything into memory at once."""
        cursor = self.collection.find(query or {}, projection)
        return await cursor.to_list(None)

    async def delete_by_scan(self, scan_id: str) -> int:
        return await self.delete_many({"scan_id": scan_id})

    async def count_by_scan(self, scan_id: str) -> int:
        return await self.count({"scan_id": scan_id})

    async def get_unique_packages(self, scan_ids: List[str]) -> int:
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$name"}},
            {"$count": "count"},
        ]
        result = await self.aggregate(pipeline)
        return result[0]["count"] if result else 0

    async def get_type_distribution(self, scan_ids: List[str]) -> List[Dict[str, Any]]:
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return await self.aggregate(pipeline)

    async def get_distinct_types(self, scan_ids: List[str]) -> List[str]:
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$type"}},
            {"$sort": {"_id": 1}},
        ]
        results = await self.aggregate(pipeline)
        return [r["_id"] for r in results if r["_id"]]
