"""MongoDB access for releases."""

from typing import Any

import pymongo
from pymongo.errors import DuplicateKeyError

from app.core.metrics import track_db_operation
from app.models.release import Release
from app.repositories.base import BaseRepository


class ReleaseRepository(BaseRepository[Release]):
    collection_name = "releases"
    model_class = Release

    async def group_by_scan(self, scan_ids: list[str]) -> dict[str, list[Release]]:
        """One query for a whole page of scans; each list is newest first."""
        if not scan_ids:
            return {}
        grouped: dict[str, list[Release]] = {}
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(
                {"scan_id": {"$in": scan_ids}},
                sort=[("released_at", pymongo.DESCENDING)],
            )
            async for doc in cursor:
                grouped.setdefault(doc["scan_id"], []).append(Release(**doc))
        return grouped

    async def record(self, release: Release) -> None:
        """Keyed on (project_id, environment, scan_id): a CI retry or a re-deploy of the same artefact
        refreshes one record, while a rollback to an older scan is a distinct one that wins on released_at."""
        key = {
            "project_id": release.project_id,
            "environment": release.environment,
            "scan_id": release.scan_id,
        }
        # Only carried when this payload names one, so a later job of the same CI pipeline
        # cannot null the version the deploy job recorded.
        changes: dict[str, Any] = {"released_at": release.released_at}
        if release.version is not None:
            changes["version"] = release.version
        with track_db_operation(self.collection_name, "update_one"):
            try:
                await self.collection.update_one(
                    key,
                    {"$set": changes, "$setOnInsert": {"_id": release.id}},
                    upsert=True,
                )
            except DuplicateKeyError:
                # A concurrent mark inserted the row between this filter miss and its insert;
                # the update cannot insert, so it cannot race again.
                await self.collection.update_one(key, {"$set": changes})
