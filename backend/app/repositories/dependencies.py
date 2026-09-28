"""Repository for dependencies."""

from typing import Any

from app.models.dependency import Dependency
from app.repositories.base import BaseRepository


class DependencyRepository(BaseRepository[Dependency]):
    collection_name = "dependencies"
    model_class = Dependency

    async def get_by_name(self, name: str) -> Dependency | None:
        return await self.find_one({"name": name})

    async def find_by_scan(self, project_id: str, scan_id: str, limit: int) -> tuple[list[Dependency], int]:
        """The scan's dependencies up to ``limit``, and how many it holds. The count costs a
        round trip only once the read has saturated, and a caller that reports the pair can tell
        a small scan from a windowed one."""
        rows = await self.find_many({"project_id": project_id, "scan_id": scan_id}, limit=limit)
        if len(rows) < limit:
            return rows, len(rows)
        return rows, await self.count_by_scan(project_id, scan_id)

    async def find_raw_by_scan(self, scan_id: str, projection: dict[str, int]) -> list[dict[str, Any]]:
        """Every dependency of one scan, unbounded: a scan's inventory is read whole to be folded."""
        return await self.collection.find({"scan_id": scan_id}, projection).to_list(None)

    async def delete_by_scan(self, scan_id: str) -> int:
        return await self.delete_many({"scan_id": scan_id})

    async def count_by_scan(self, project_id: str, scan_id: str) -> int:
        return await self.count({"project_id": project_id, "scan_id": scan_id})

    async def get_unique_packages(self, scan_ids: list[str]) -> int:
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$name"}},
            {"$count": "count"},
        ]
        result = await self.aggregate(pipeline)
        return result[0]["count"] if result else 0

    async def get_type_distribution(self, scan_ids: list[str]) -> list[dict[str, Any]]:
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return await self.aggregate(pipeline)

    async def get_distinct_types(self, scan_ids: list[str]) -> list[str]:
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$type"}},
            {"$sort": {"_id": 1}},
        ]
        results = await self.aggregate(pipeline)
        return [r["_id"] for r in results if r["_id"]]
