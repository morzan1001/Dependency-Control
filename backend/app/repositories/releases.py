from collections.abc import Sequence
from typing import Any

import pymongo
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.models.release import Release
from app.repositories.base import BaseRepository

RELEASES_UPSERT_KEY_NAME = "releases_upsert_key"
# One release per (project, environment, scan), shared by the upsert filter and the unique index behind it.
RELEASES_UPSERT_KEY_FIELDS: tuple[str, ...] = ("project_id", "environment", "scan_id")

RELEASES_LATEST_LOOKUP_NAME = "releases_latest_lookup"
# BSON dates are milliseconds, so ties break on _id; the sort is its index's tail, keeping the seek indexed.
RELEASES_LATEST_SORT: list[tuple[str, int]] = [("released_at", pymongo.DESCENDING), ("_id", pymongo.ASCENDING)]
RELEASES_LATEST_LOOKUP_KEY: list[tuple[str, int]] = [
    ("project_id", pymongo.ASCENDING),
    ("environment", pymongo.ASCENDING),
    *RELEASES_LATEST_SORT,
]
# The index order left once project_id is matched by equality.
RELEASES_ENVIRONMENT_SORT = RELEASES_LATEST_LOOKUP_KEY[1:]


class ReleaseRepository(BaseRepository[Release]):
    collection_name = "releases"
    model_class = Release

    async def group_by_scan(self, scan_ids: list[str]) -> dict[str, list[Release]]:
        if not scan_ids:
            return {}
        grouped: dict[str, list[Release]] = {}
        cursor = self.collection.find({"scan_id": {"$in": scan_ids}}, sort=RELEASES_LATEST_SORT)
        async for doc in cursor:
            grouped.setdefault(doc["scan_id"], []).append(Release(**doc))
        return grouped

    async def page(self, query: dict[str, Any], skip: int, limit: int) -> list[dict[str, Any]]:
        cursor = self.collection.find(query, sort=RELEASES_LATEST_SORT).skip(skip).limit(limit)
        rows: list[dict[str, Any]] = await cursor.to_list(limit)
        return rows

    async def record(self, release: Release, version_fallback: str | None = None) -> dict[str, Any] | None:
        """A re-deploy refreshes its record, a rollback adds its own; None only if a concurrent withdraw removed it."""
        key = {field: getattr(release, field) for field in RELEASES_UPSERT_KEY_FIELDS}
        # Only when named, so a later job cannot null the deploy job's version, nor an unset CI tag ("") name it.
        changes: dict[str, Any] = {"released_at": release.released_at}
        inserted: dict[str, Any] = {"_id": release.id}
        if release.version:
            changes["version"] = release.version
        elif version_fallback:
            # A first mark only, so an unversioned re-mark keeps the version a deploy job named.
            inserted["version"] = version_fallback
        try:
            row: dict[str, Any] | None = await self.collection.find_one_and_update(
                key,
                {"$set": changes, "$setOnInsert": inserted},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
        except DuplicateKeyError:
            # A concurrent mark inserted the row first; this update cannot insert, so it cannot race again.
            row = await self.collection.find_one_and_update(
                key, {"$set": changes}, return_document=ReturnDocument.AFTER
            )
        return row

    async def withdraw(self, project_id: str, environment: str, scan_id: str) -> list[str] | None:
        scan_key = {"project_id": project_id, "scan_id": scan_id}
        if not (await self.collection.delete_one({**scan_key, "environment": environment})).deleted_count:
            return None
        return sorted(await self.collection.distinct("environment", scan_key))

    async def released_among(self, scan_ids: Sequence[str]) -> set[str]:
        return set(await self.collection.distinct("scan_id", {"scan_id": {"$in": list(scan_ids)}}))

    async def environments(self, project_ids: Sequence[str]) -> list[str]:
        return sorted(await self.collection.distinct("environment", {"project_id": {"$in": list(project_ids)}}))

    async def latest_for_environment(self, project_id: str, environment: str) -> dict[str, Any] | None:
        return await self.collection.find_one(
            {"project_id": project_id, "environment": environment}, sort=RELEASES_LATEST_SORT
        )
