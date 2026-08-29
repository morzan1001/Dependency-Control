"""Reads over the per-scan update-frequency rollups and over the scan window they summarise."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import batched
from typing import Any

from app.core.constants import SCAN_USABLE_STATUSES
from app.core.metrics import track_db_operation
from app.models.update_frequency import UPDATE_DELTA_SCHEMA_VERSION, ScanOutdatedSet, ScanUpdateDelta
from app.repositories.base import BaseRepository
from app.repositories.scans import ScanRepository

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


def _as_utc(at: datetime) -> datetime:
    """Mongo returns naive UTC datetimes."""
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def _chain_order(doc: dict[str, Any]) -> tuple[datetime, str]:
    """The writer's total order over one branch."""
    return (_as_utc(doc["scan_created_at"]), doc["_id"])


@dataclass(frozen=True)
class LedgerEntry:
    """What the reconcile knows about one delta without reading the delta itself."""

    schema_version: int | None
    prev_scan_id: str | None
    prev_created_at: datetime | None


def _ledger_entry(pushed: dict[str, Any]) -> LedgerEntry:
    prev_at = pushed.get("prev_at")
    return LedgerEntry(
        pushed.get("v"),
        pushed.get("prev"),
        _as_utc(prev_at) if isinstance(prev_at, datetime) else None,
    )


@dataclass(frozen=True)
class BranchWindowActivity:
    """What one branch of one project really holds in the window, before any fold drops a scan."""

    commit_count: int
    last_scan_at: datetime


# Sorts last on the recency tie-break.
_UNDATED = datetime.min.replace(tzinfo=timezone.utc)

# The index on (project_id, branch, created_at) bounds the scan to the batch's projects;
# status and is_rescan are not in it, so their documents are fetched. A whole-scope
# comparison touches at most the 50k documents of the collection once and groups them
# into one row per branch holding that branch's commit hashes, which keeps every batch
# far under the 100 MB limit.
_SCAN_WINDOW_PROJECT_BATCH = 200

# Neither read path analyses more than this many documents of one branch: the live walk
# fetches at most this many scans, and the rollup folds at most this many deltas. A
# branch busier than that is truncated to the same newest stretch on both paths, so
# what the cap left out is what neither path was going to read.
WINDOW_HARD_LIMIT = 1000

# Two scans of one commit carry the same SBOM, so both read paths keep only the first
# of a run. Counting documents instead would read a CI retry storm as missing data.
# A scan that names no commit stands for itself, matching collapse_same_commit_runs.
_COMMIT_TOKEN = {"$cond": [{"$eq": [{"$ifNull": ["$commit_hash", ""]}, ""]}, "$_id", "$commit_hash"]}


def _usable_scan_match(since: datetime | None) -> dict[str, Any]:
    """The scans the rollup writer accepts and both read paths fold."""
    scoped: dict[str, Any] = {"status": {"$in": SCAN_USABLE_STATUSES}, "is_rescan": {"$ne": True}}
    if since is not None:
        scoped["created_at"] = {"$gte": since}
    return scoped


def _named_branch(row_id: Any) -> tuple[str, str] | None:
    """The (project, branch) a ``$group`` row names, or None when it is missing either.

    A grouping key drops the field entirely when a document lacks it, and a scan that
    names no branch cannot be diffed against another, so both read paths skip it.
    """
    project_id, branch = row_id.get("p"), row_id.get("b")
    if not isinstance(project_id, str) or not isinstance(branch, str) or not branch:
        return None
    return project_id, branch


async def window_scans_by_branch(
    scan_repo: ScanRepository,
    project_ids: Sequence[str],
    since: datetime | None,
) -> dict[tuple[str, str], BranchWindowActivity]:
    """Comparable commits per (project, branch), over the window itself when one is given.

    Both read paths choose their branch from these counts, so neither can settle on a
    branch the other would not, and both can tell how much of the window their numbers
    actually cover.
    """
    scoped = _usable_scan_match(since)

    activity: dict[tuple[str, str], BranchWindowActivity] = {}
    for batch in batched(project_ids, _SCAN_WINDOW_PROJECT_BATCH):
        pipeline = [
            {"$match": {"project_id": {"$in": list(batch)}, **scoped}},
            {"$addFields": {"_commit": _COMMIT_TOKEN}},
            {
                "$group": {
                    "_id": {"p": "$project_id", "b": "$branch"},
                    "commits": {"$addToSet": "$_commit"},
                    "last_scan_at": {"$max": "$created_at"},
                }
            },
            {"$project": {"commit_count": {"$size": "$commits"}, "last_scan_at": 1}},
        ]
        for row in await scan_repo.aggregate(pipeline):
            chain = _named_branch(row["_id"])
            if chain is None:
                continue
            last_scan_at = row["last_scan_at"]
            # Archive restore can insert a scan date as an ISO string, which $max hands back verbatim.
            moment = _as_utc(last_scan_at) if isinstance(last_scan_at, datetime) else _UNDATED
            activity[chain] = BranchWindowActivity(int(row["commit_count"]), moment)
    return activity


async def window_scan_ids_by_branch(
    scan_repo: ScanRepository,
    project_ids: Sequence[str],
    since: datetime,
) -> dict[tuple[str, str], list[tuple[str, datetime]]]:
    """Every in-window scan the writer owes a delta, per (project, branch), unordered.

    Deliberately not ``window_scans_by_branch``: that one collapses a commit's scans
    into one entry, while the writer records one delta per scan, so a CI retry storm
    would read as a hole in the ledger.

    A date floor brackets by BSON type, so a scan whose ``created_at`` is missing or a
    string drops out here exactly as it does in the writer, which cannot place it on a
    timeline either.
    """
    scans: dict[tuple[str, str], list[tuple[str, datetime]]] = {}
    for batch in batched(project_ids, _SCAN_WINDOW_PROJECT_BATCH):
        pipeline = [
            {"$match": {"project_id": {"$in": list(batch)}, **_usable_scan_match(since)}},
            {
                "$group": {
                    "_id": {"p": "$project_id", "b": "$branch"},
                    "scans": {"$push": {"i": "$_id", "t": "$created_at"}},
                }
            },
        ]
        for row in await scan_repo.aggregate(pipeline):
            chain = _named_branch(row["_id"])
            if chain is None:
                continue
            scans[chain] = [(entry["i"], _as_utc(entry["t"])) for entry in row["scans"]]
    return scans


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
                chain = _named_branch(row["_id"])
                if chain is None:
                    continue
                project_id, branch = chain
                deltas = sorted(row["deltas"], key=_chain_order)
                for delta in deltas:
                    # Carried in the group key rather than per document; the fold
                    # rejects a window that does not name its project and branch.
                    delta["project_id"], delta["branch"] = project_id, branch
                buckets[project_id, branch] = deltas
        return buckets

    async def window_ledger_by_branch(
        self, project_ids: Sequence[str], since: datetime
    ) -> dict[tuple[str, str], dict[str, LedgerEntry]]:
        """Version and predecessor link of every in-window delta, keyed by scan id, per chain.

        Only those three fields travel, not the document: the reconcile compares ledger
        membership and the chain links, and pushing whole deltas would make the nightly
        census as heavy as the comparison endpoint's fold.
        """
        chains: dict[tuple[str, str], dict[str, LedgerEntry]] = {}
        for batch in batched(project_ids, _WINDOW_PROJECT_BATCH):
            pipeline = [
                {"$match": {"project_id": {"$in": list(batch)}, "scan_created_at": {"$gte": since}}},
                {
                    "$group": {
                        "_id": {"p": "$project_id", "b": "$branch"},
                        "deltas": {
                            "$push": {
                                "i": "$_id",
                                "v": "$schema_version",
                                "prev": "$prev_scan_id",
                                "prev_at": "$prev_created_at",
                            }
                        },
                    }
                },
            ]
            with track_db_operation(self.collection_name, "aggregate"):
                rows = await self.collection.aggregate(pipeline, allowDiskUse=False).to_list(None)
            for row in rows:
                chain = _named_branch(row["_id"])
                if chain is None:
                    continue
                chains[chain] = {entry["i"]: _ledger_entry(entry) for entry in row["deltas"]}
        return chains

    async def find_dependents(self, project_id: str, branch: str, prev_scan_ids: Sequence[str]) -> list[dict[str, Any]]:
        """Deltas of the branch that were diffed against one of the given scans."""
        if not prev_scan_ids:
            return []
        with track_db_operation(self.collection_name, "find"):
            docs = await self.collection.find(
                {"project_id": project_id, "branch": branch, "prev_scan_id": {"$in": list(prev_scan_ids)}},
                _NEIGHBOUR_PROJECTION,
            ).to_list(None)
        return docs

    async def find_project_window(
        self, project_id: str, branch: str, since: datetime, limit: int
    ) -> list[dict[str, Any]]:
        """The newest ``limit`` in-window deltas of one branch, oldest first, arrays included.

        The limit is per branch, as the live path's is: spending it across every
        branch of a project would truncate the analysed one behind the others.
        """
        with track_db_operation(self.collection_name, "find"):
            docs = (
                await self.collection.find(
                    {
                        "project_id": project_id,
                        "branch": branch,
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
