"""Repositories for the per-scan update-frequency rollups."""

from collections.abc import Sequence
from datetime import datetime, timezone
from itertools import batched
from typing import Any

from app.core.metrics import track_db_operation
from app.models.update_frequency import UPDATE_DELTA_SCHEMA_VERSION, ScanOutdatedSet, ScanUpdateDelta
from app.repositories.base import BaseRepository

_NEIGHBOUR_PROJECTION = {"_id": 1, "scan_created_at": 1, "prev_scan_id": 1, "dep_count": 1}

# Everything the pure fold needs for a comparison row. updates_sample and
# prev_created_at are left behind: only the single-project timeline reads them,
# and they would multiply the size of a $group that already holds every delta.
_WINDOW_FIELDS = {
    "_id": "$_id",
    "scan_created_at": "$scan_created_at",
    "commit_hash": "$commit_hash",
    "prev_scan_id": "$prev_scan_id",
    "dep_count": "$dep_count",
    "updates": "$updates",
    "outdated_count": "$outdated_count",
    "outdated_added": "$outdated_added",
    "outdated_resolved": "$outdated_resolved",
    "eco": "$eco",
    "error": "$error",
}

# A scan whose predecessor carried no outdated analysis reports its whole outdated set
# in outdated_added, so a delta can reach ~11 KB instead of ~500 B. Batching by project
# keeps the $group output around 2-10 MB in practice, far under the 100 MB limit for
# blocking stages. It is not a hard bound: batches are sized by project count, so a
# batch of unusually large projects made entirely of such scans could still exceed it.
# allowDiskUse stays off so that case fails loudly instead of silently spilling.
_WINDOW_PROJECT_BATCH = 100


def _chain_order(doc: dict[str, Any]) -> tuple[datetime, str]:
    """The writer's total order over one branch, normalised: Mongo returns naive UTC."""
    at = doc["scan_created_at"]
    return (at if at.tzinfo else at.replace(tzinfo=timezone.utc), doc["_id"])


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

    async def group_window_by_branch(
        self, project_ids: Sequence[str], since: datetime
    ) -> dict[tuple[str, str], list[dict[str, Any]]]:
        """In-window deltas of every project, bucketed by (project, branch), oldest first.

        Grouping only buckets; every metric stays in the pure fold, so the two
        cannot drift apart.
        """
        buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for batch in batched(project_ids, _WINDOW_PROJECT_BATCH):
            pipeline = [
                {
                    "$match": {
                        "project_id": {"$in": list(batch)},
                        "scan_created_at": {"$gte": since},
                        "schema_version": UPDATE_DELTA_SCHEMA_VERSION,
                    }
                },
                {
                    "$group": {
                        "_id": {"p": "$project_id", "b": "$branch"},
                        "deltas": {"$push": _WINDOW_FIELDS},
                    }
                },
            ]
            with track_db_operation(self.collection_name, "aggregate"):
                # allowDiskUse stays off so outgrowing the batch sizing fails loudly
                # instead of quietly spilling to the mongod's disk.
                rows = await self.collection.aggregate(pipeline, allowDiskUse=False).to_list(None)
            for row in rows:
                project_id, branch = row["_id"]["p"], row["_id"]["b"]
                deltas = sorted(row["deltas"], key=_chain_order)
                for delta in deltas:
                    # Carried in the group key rather than per document; the fold
                    # rejects a window that does not name its project and branch.
                    delta["project_id"], delta["branch"] = project_id, branch
                buckets[project_id, branch] = deltas
        return buckets

    async def find_project_window(self, project_id: str, since: datetime, limit: int) -> list[dict[str, Any]]:
        """The newest ``limit`` in-window deltas of one project, oldest first, arrays included."""
        with track_db_operation(self.collection_name, "find"):
            docs = (
                await self.collection.find(
                    {
                        "project_id": project_id,
                        "scan_created_at": {"$gte": since},
                        "schema_version": UPDATE_DELTA_SCHEMA_VERSION,
                    }
                )
                .sort([("scan_created_at", -1), ("_id", -1)])
                .limit(limit)
                .to_list(limit)
            )
        return sorted(docs, key=_chain_order)

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

    async def names_by_scan(self, scan_ids: Sequence[str]) -> dict[str, set[str]]:
        """Outdated package names per scan; scans without a stored set are absent."""
        if not scan_ids:
            return {}
        with track_db_operation(self.collection_name, "find"):
            docs = await self.collection.find({"_id": {"$in": list(scan_ids)}}, {"names": 1}).to_list(len(scan_ids))
        return {doc["_id"]: set(doc.get("names") or ()) for doc in docs}
