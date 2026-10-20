from typing import Any

from pymongo import UpdateOne
from pymongo.errors import BulkWriteError

from app.core.purl import package_identity_expr
from app.models.dependency import Dependency
from app.repositories.base import DUPLICATE_KEY_ERROR, BaseRepository


class DependencyRepository(BaseRepository[Dependency]):
    collection_name = "dependencies"
    model_class = Dependency

    async def upsert_many(self, dependencies: list[Dependency], fresh: bool = False) -> None:
        if fresh:
            try:
                await self.collection.insert_many([d.model_dump(by_alias=True) for d in dependencies], ordered=False)
                return
            except BulkWriteError as e:
                errors = e.details["writeErrors"]
                if e.details.get("writeConcernErrors") or any(err["code"] != DUPLICATE_KEY_ERROR for err in errors):
                    raise
                dependencies = [dependencies[err["index"]] for err in errors]
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

    async def get_unique_packages(self, scan_ids: list[str]) -> int:
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": package_identity_expr()}},
            {"$count": "count"},
        ]
        result = await self.aggregate(pipeline)
        return result[0]["count"] if result else 0

    async def get_type_distribution(self, scan_ids: list[str]) -> list[dict[str, Any]]:
        from app.api.v1.helpers.sorting import case_insensitive_sort  # app.api.v1.helpers imports this module

        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            # Ties break by name: $group order is arbitrary and the summary tile names the leading types.
            *case_insensitive_sort([("count", -1), ("_id", 1)], {"_id"}),
        ]
        return await self.aggregate(pipeline)

    async def get_top_usage(self, scan_ids: list[str], limit: int, type_filter: str | None) -> list[dict[str, Any]]:
        from app.api.v1.helpers.sorting import case_insensitive_sort  # app.api.v1.helpers imports this module

        match: dict[str, Any] = {"scan_id": {"$in": scan_ids}}
        if type_filter:
            match["type"] = type_filter
        pipeline: list[dict[str, Any]] = [
            {"$match": match},
            {
                "$group": {
                    "_id": package_identity_expr(),
                    "name": {"$min": "$name"},
                    "type": {"$min": "$type"},
                    "group": {"$max": "$group"},
                    "versions": {"$addToSet": "$version"},
                    "project_ids": {"$addToSet": "$project_id"},
                    "total_occurrences": {"$sum": 1},
                }
            },
            {
                "$project": {
                    "name": 1,
                    "type": 1,
                    "group": 1,
                    "versions": 1,
                    "version_count": {"$size": "$versions"},
                    "project_count": {"$size": "$project_ids"},
                    "total_occurrences": 1,
                }
            },
            *case_insensitive_sort(
                [("project_count", -1), ("total_occurrences", -1), ("name", 1), ("_id", 1)], {"name"}
            ),
            {"$limit": limit},
        ]
        return await self.aggregate(pipeline)
