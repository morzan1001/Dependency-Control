from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import batched
from typing import Any

from app.core import UNDATED
from app.models.update_frequency import UPDATE_DELTA_SCHEMA_VERSION, ScanOutdatedSet, ScanUpdateDelta
from app.repositories.base import BaseRepository
from app.repositories.scans import USABLE_BUILD_MATCH, ScanRepository

_NEIGHBOUR_PROJECTION = {"_id": 1, "scan_created_at": 1, "prev_scan_id": 1, "dep_count": 1}

# Everything the pure fold needs for a comparison row.
_WINDOW_PROJECTION = {
    "_id": 1,
    "project_id": 1,
    "branch": 1,
    "scan_created_at": 1,
    "commit_hash": 1,
    "prev_scan_id": 1,
    "dep_count": 1,
    "updates": 1,
    "outdated_count": 1,
    "outdated_added": 1,
    "outdated_resolved": 1,
    "error": 1,
}

# Bounds one read's $in list; a delta can reach ~11 KB when its predecessor had no outdated analysis.
_WINDOW_PROJECT_BATCH = 100


def _chain_order(doc: dict[str, Any]) -> tuple[datetime, str]:
    """The writer's total order over one branch."""
    return (doc["scan_created_at"], doc["_id"])


@dataclass(frozen=True)
class LedgerEntry:
    schema_version: int | None
    prev_scan_id: str | None
    prev_created_at: datetime | None
    scan_created_at: datetime
    # Carries dependencies and no writer failure, so a later scan can be diffed against it.
    comparable: bool


def _ledger_entry(pushed: dict[str, Any]) -> LedgerEntry:
    prev_at = pushed.get("prev_at")
    return LedgerEntry(
        pushed.get("v"),
        pushed.get("prev"),
        prev_at if isinstance(prev_at, datetime) else None,
        pushed["at"],
        int(pushed.get("n") or 0) > 0 and not pushed.get("e"),
    )


@dataclass(frozen=True)
class BranchWindowActivity:
    """Scans per commit, since a commit is unmeasurable only if all its scans say so; one without a delta is a hole."""

    scans_per_commit: dict[str, int]
    last_scan_at: datetime

    @property
    def commit_count(self) -> int:
        return len(self.scans_per_commit)


# One row per branch holds its commit hashes, so even a 50k-scan scope keeps each batch far under the 100 MB limit.
_SCAN_WINDOW_PROJECT_BATCH = 200

# Both read paths stop at this many documents of one branch, so they truncate a busier one to the same stretch.
WINDOW_HARD_LIMIT = 1000

# Coverage counts commits, as counting documents reads a CI retry storm as missing data; a commitless scan counts alone.
_COMMIT_TOKEN = {"$cond": [{"$eq": [{"$ifNull": ["$commit_hash", ""]}, ""]}, "$_id", "$commit_hash"]}


def usable_scan_match(since: datetime | None) -> dict[str, Any]:
    """The usable builds both read paths fold, from ``since`` on."""
    scoped: dict[str, Any] = dict(USABLE_BUILD_MATCH)
    if since is not None:
        scoped["created_at"] = {"$gte": since}
    return scoped


def _named_branch(row_id: Any) -> tuple[str, str] | None:
    """$group drops a missing key field, and a scan naming no branch cannot be diffed, so both read paths skip it."""
    project_id, branch = row_id.get("p"), row_id.get("b")
    if not isinstance(project_id, str) or not isinstance(branch, str) or not branch:
        return None
    return project_id, branch


async def window_scans_by_branch(
    scan_repo: ScanRepository,
    project_ids: Sequence[str],
    since: datetime | None,
) -> dict[str, dict[str, BranchWindowActivity]]:
    """Both read paths pick their branch from these counts, so neither settles on a branch the other would not."""
    # A findings-only scan holds no dependencies to compare; $ne keeps scans older than sbom_refs.
    scoped = {**usable_scan_match(since), "sbom_refs": {"$ne": []}}

    activity: dict[str, dict[str, BranchWindowActivity]] = {}
    for batch in batched(project_ids, _SCAN_WINDOW_PROJECT_BATCH, strict=False):
        pipeline = [
            {"$match": {"project_id": {"$in": list(batch)}, **scoped}},
            {"$addFields": {"_commit": _COMMIT_TOKEN}},
            {
                "$group": {
                    "_id": {"p": "$project_id", "b": "$branch", "c": "$_commit"},
                    "scans": {"$sum": 1},
                    "last_scan_at": {"$max": "$created_at"},
                }
            },
            {
                "$group": {
                    "_id": {"p": "$_id.p", "b": "$_id.b"},
                    "commits": {"$push": {"t": "$_id.c", "n": "$scans"}},
                    "last_scan_at": {"$max": "$last_scan_at"},
                }
            },
        ]
        for row in await scan_repo.aggregate(pipeline):
            chain = _named_branch(row["_id"])
            if chain is None:
                continue
            last_scan_at = row["last_scan_at"]
            # Archive restore can insert a scan date as an ISO string, which $max hands back verbatim.
            moment = last_scan_at if isinstance(last_scan_at, datetime) else UNDATED
            per_commit = {c["t"]: int(c["n"]) for c in row["commits"] if isinstance(c.get("t"), str)}
            project_id, branch = chain
            activity.setdefault(project_id, {})[branch] = BranchWindowActivity(per_commit, moment)
    return activity


async def window_scan_ids_by_branch(
    scan_repo: ScanRepository,
    project_ids: Sequence[str],
    since: datetime,
) -> dict[tuple[str, str], list[tuple[str, datetime]]]:
    """Per scan, as the writer owes each scan a delta; a non-date created_at drops out here as in the writer."""
    scans: dict[tuple[str, str], list[tuple[str, datetime]]] = {}
    for batch in batched(project_ids, _SCAN_WINDOW_PROJECT_BATCH, strict=False):
        pipeline = [
            {"$match": {"project_id": {"$in": list(batch)}, **usable_scan_match(since)}},
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
            scans[chain] = [(entry["i"], entry["t"]) for entry in row["scans"]]
    return scans


def _outside(at: datetime, at_id: str, operator: str) -> list[dict[str, Any]]:
    """_id breaks same-millisecond ties, so two such scans neither both become a baseline nor point at each other."""
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
    ) -> dict[str, dict[str, list[dict[str, Any]]]]:
        """Bucketed in Python: a $group over 8.7 MB of deltas' outdated arrays exceeded a blocking stage's 100 MB."""
        buckets: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for batch in batched(project_ids, _WINDOW_PROJECT_BATCH, strict=False):
            query = {
                "project_id": {"$in": list(batch)},
                "scan_created_at": {"$gte": since},
                "schema_version": UPDATE_DELTA_SCHEMA_VERSION,
            }
            # Unsorted: an in-memory sort has the group's ceiling, and each chain is ordered below anyway.
            docs = await self.collection.find(query, _WINDOW_PROJECTION).to_list(None)
            for doc in docs:
                chain = _named_branch({"p": doc.get("project_id"), "b": doc.get("branch")})
                if chain is None:
                    continue
                project_id, branch = chain
                buckets.setdefault(project_id, {}).setdefault(branch, []).append(doc)
        for branches in buckets.values():
            for deltas in branches.values():
                deltas.sort(key=_chain_order)
        return buckets

    async def window_ledger_by_branch(
        self, project_ids: Sequence[str], since: datetime
    ) -> dict[tuple[str, str], dict[str, LedgerEntry]]:
        """Only chain fields travel; whole deltas would make the nightly census as heavy as the comparison's fold."""
        chains: dict[tuple[str, str], dict[str, LedgerEntry]] = {}
        for batch in batched(project_ids, _WINDOW_PROJECT_BATCH, strict=False):
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
                                "at": "$scan_created_at",
                                "n": "$dep_count",
                                "e": "$error",
                            }
                        },
                    }
                },
            ]
            rows = await self.collection.aggregate(pipeline, allowDiskUse=False).to_list(None)
            for row in rows:
                chain = _named_branch(row["_id"])
                if chain is None:
                    continue
                chains[chain] = {entry["i"]: _ledger_entry(entry) for entry in row["deltas"]}
        return chains

    async def find_dependents(self, project_id: str, branch: str, prev_scan_ids: Sequence[str]) -> list[dict[str, Any]]:
        if not prev_scan_ids:
            return []
        return await self.collection.find(
            {"project_id": project_id, "branch": branch, "prev_scan_id": {"$in": list(prev_scan_ids)}},
            _NEIGHBOUR_PROJECTION,
        ).to_list(None)

    async def _neighbour(self, query: dict[str, Any], direction: int) -> dict[str, Any] | None:
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
        if not scan_ids:
            return {}
        docs = await self.collection.find({"_id": {"$in": list(scan_ids)}}, {"names": 1}).to_list(len(scan_ids))
        return {doc["_id"]: set(doc.get("names") or ()) for doc in docs}
