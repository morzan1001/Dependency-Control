"""MongoDB access for releases."""

from collections.abc import Sequence
from typing import Any

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.init_db import RELEASES_LATEST_SORT, RELEASES_UPSERT_KEY_FIELDS
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
        cursor = self.collection.find({"scan_id": {"$in": scan_ids}}, sort=RELEASES_LATEST_SORT)
        async for doc in cursor:
            grouped.setdefault(doc["scan_id"], []).append(Release(**doc))
        return grouped

    async def record(self, release: Release) -> dict[str, Any] | None:
        """Keyed on (project_id, environment, scan_id): a CI retry or a re-deploy of the same artefact
        refreshes one record, while a rollback to an older scan is a distinct one that wins on released_at.

        Answers with the stored row; None only when a concurrent withdraw removed it in between.
        """
        key = {field: getattr(release, field) for field in RELEASES_UPSERT_KEY_FIELDS}
        # Only carried when this payload names one, so a later job of the same CI pipeline cannot
        # null the version the deploy job recorded, nor a CI's unset tag ("") name the release.
        changes: dict[str, Any] = {"released_at": release.released_at}
        if release.version:
            changes["version"] = release.version
        try:
            row: dict[str, Any] | None = await self.collection.find_one_and_update(
                key,
                {"$set": changes, "$setOnInsert": {"_id": release.id}},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
        except DuplicateKeyError:
            # A concurrent mark inserted the row between this filter miss and its insert;
            # the update cannot insert, so it cannot race again.
            row = await self.collection.find_one_and_update(
                key, {"$set": changes}, return_document=ReturnDocument.AFTER
            )
        return row

    async def withdraw(self, project_id: str, environment: str, scan_id: str) -> list[str] | None:
        """Remove one environment's record; the environments the scan still runs in, or None if it ran in none."""
        scan_key = {"project_id": project_id, "scan_id": scan_id}
        if not (await self.collection.delete_one({**scan_key, "environment": environment})).deleted_count:
            return None
        return sorted(await self.collection.distinct("environment", scan_key))

    async def released_among(self, scan_ids: Sequence[str]) -> set[str]:
        return set(await self.collection.distinct("scan_id", {"scan_id": {"$in": list(scan_ids)}}))

    async def latest_for_environment(self, project_id: str, environment: str) -> dict[str, Any] | None:
        return await self.collection.find_one(
            {"project_id": project_id, "environment": environment}, sort=RELEASES_LATEST_SORT
        )
