"""Repository for dependencies."""

from typing import Any

from pymongo import UpdateOne

from app.core.purl import package_identity_expr
from app.models.dependency import Dependency
from app.repositories.base import BaseRepository, find_window


class DependencyRepository(BaseRepository[Dependency]):
    collection_name = "dependencies"
    model_class = Dependency

    async def get_by_name(self, name: str) -> Dependency | None:
        return await self.find_one({"name": name})

    async def find_by_scan(self, project_id: str, scan_id: str, limit: int) -> tuple[list[Dependency], int]:
        """The scan's dependencies up to ``limit``, and how many it holds."""
        rows, total = await find_window(self.collection, {"project_id": project_id, "scan_id": scan_id}, limit)
        return self._to_model_list(rows), total

    async def upsert_many(self, dependencies: list[Dependency]) -> None:
        """Write each dependency over its scan's (name, version, purl) row; the row keeps its newest created_at."""
        await self.collection.bulk_write(
            [
                UpdateOne(
                    {"scan_id": d.scan_id, "name": d.name, "version": d.version, "purl": d.purl},
                    {
                        "$set": d.model_dump(by_alias=True, exclude={"id", "created_at"}),
                        "$max": {"created_at": d.created_at},
                        "$setOnInsert": {"_id": d.id},
                    },
                    upsert=True,
                )
                for d in dependencies
            ],
            ordered=False,
        )

    async def count_by_scan(self, project_id: str, scan_id: str) -> int:
        return await self.count({"project_id": project_id, "scan_id": scan_id})

    async def get_unique_packages(self, scan_ids: list[str]) -> int:
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": package_identity_expr()}},
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
