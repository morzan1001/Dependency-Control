"""Repositories for the per-scan update-frequency rollups."""

from datetime import datetime
from typing import Any

from app.core.metrics import track_db_operation
from app.models.update_frequency import ScanOutdatedSet, ScanUpdateDelta
from app.repositories.base import BaseRepository

_NEIGHBOUR_PROJECTION = {"_id": 1, "scan_created_at": 1, "prev_scan_id": 1, "dep_count": 1}


def _outside(at: datetime, at_id: str, operator: str) -> list[dict[str, Any]]:
    """Scans ordered by ``(scan_created_at, _id)``, the tie-break for one BSON millisecond.

    Ordering equal timestamps by ``_id`` keeps the chain a strict total order, so
    two scans of the same millisecond neither both become a baseline nor point at
    each other.
    """
    return [{"scan_created_at": {operator: at}}, {"scan_created_at": at, "_id": {operator: at_id}}]


class ScanUpdateDeltaRepository(BaseRepository[ScanUpdateDelta]):
    collection_name = "scan_update_deltas"
    model_class = ScanUpdateDelta

    async def save(self, delta: ScanUpdateDelta) -> None:
        doc = delta.model_dump(by_alias=True)
        # _id travels in the filter: Mongo rejects an update that touches the immutable field.
        await self.upsert({"_id": doc.pop("_id")}, doc)

    async def find_predecessor(
        self, project_id: str, branch: str, before: datetime, before_id: str
    ) -> dict[str, Any] | None:
        """Newest delta of the branch that carries dependencies and precedes the given scan."""
        return await self._neighbour(
            {
                "project_id": project_id,
                "branch": branch,
                "dep_count": {"$gt": 0},
                "$or": _outside(before, before_id, "$lt"),
            },
            direction=-1,
        )

    async def find_successor(
        self, project_id: str, branch: str, after: datetime, after_id: str
    ) -> dict[str, Any] | None:
        """Oldest delta of the branch following the given scan, whatever its dependency count."""
        return await self._neighbour(
            {
                "project_id": project_id,
                "branch": branch,
                "$or": _outside(after, after_id, "$gt"),
            },
            direction=1,
        )

    async def _neighbour(self, query: dict[str, Any], direction: int) -> dict[str, Any] | None:
        with track_db_operation(self.collection_name, "find"):
            docs = (
                await self.collection.find(query, _NEIGHBOUR_PROJECTION)
                .sort([("scan_created_at", direction), ("_id", direction)])
                .limit(1)
                .to_list(1)
            )
        return docs[0] if docs else None


class ScanOutdatedSetRepository(BaseRepository[ScanOutdatedSet]):
    collection_name = "scan_outdated_sets"
    model_class = ScanOutdatedSet

    async def save(self, outdated_set: ScanOutdatedSet) -> None:
        doc = outdated_set.model_dump(by_alias=True)
        await self.upsert({"_id": doc.pop("_id")}, doc)
