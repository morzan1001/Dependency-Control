from collections import Counter
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import batched
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection

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

_LEDGER_PROJECTION = {
    "_id": 1,
    "project_id": 1,
    "branch": 1,
    "schema_version": 1,
    "prev_scan_id": 1,
    "prev_created_at": 1,
    "scan_created_at": 1,
    "dep_count": 1,
    "error": 1,
}

_SCAN_ID_PROJECTION = {"_id": 1, "project_id": 1, "branch": 1, "created_at": 1}
_ACTIVITY_PROJECTION = {**_SCAN_ID_PROJECTION, "commit_hash": 1}

# Bounds one read's $in list.
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


def _ledger_entry(delta: dict[str, Any]) -> LedgerEntry:
    prev_at = delta.get("prev_created_at")
    return LedgerEntry(
        delta.get("schema_version"),
        delta.get("prev_scan_id"),
        prev_at if isinstance(prev_at, datetime) else None,
        delta["scan_created_at"],
        int(delta.get("dep_count") or 0) > 0 and not delta.get("error"),
    )


@dataclass(frozen=True)
class BranchWindowActivity:
    """Scans per commit, since a commit is unmeasurable only if all its scans say so; one without a delta is a hole."""

    scans_per_commit: dict[str, int]
    last_scan_at: datetime

    @property
    def commit_count(self) -> int:
        return len(self.scans_per_commit)


# Both read paths stop at this many documents of one branch, so they truncate a busier one to the same stretch.
WINDOW_HARD_LIMIT = 1000


def usable_scan_match(since: datetime | None) -> dict[str, Any]:
    """The usable builds both read paths fold, from ``since`` on; an archive restore can store created_at as text."""
    return {**USABLE_BUILD_MATCH, "created_at": {"$type": "date"} if since is None else {"$gte": since}}


def _named_branch(doc: dict[str, Any]) -> tuple[str, str] | None:
    """A scan naming no branch cannot be diffed, so every window read skips it."""
    project_id, branch = doc.get("project_id"), doc.get("branch")
    if not isinstance(project_id, str) or not isinstance(branch, str) or not branch:
        return None
    return project_id, branch


async def _window_docs(
    collection: AsyncIOMotorCollection,
    project_ids: Sequence[str],
    scope: dict[str, Any],
    projection: dict[str, int],
) -> AsyncIterator[tuple[tuple[str, str], dict[str, Any]]]:
    """Streamed for bucketing in Python, as a $group over a window's documents outgrew a blocking stage's 100 MB."""
    for batch in batched(project_ids, _WINDOW_PROJECT_BATCH, strict=False):
        # Unsorted: a blocking sort has the same ceiling.
        async for doc in collection.find({"project_id": {"$in": list(batch)}, **scope}, projection):
            chain = _named_branch(doc)
            if chain is not None:
                yield chain, doc


def _commit_token(scan: dict[str, Any]) -> Any:
    """Commits, not scans: a CI retry storm would read as missing data; a commitless scan counts alone."""
    commit = scan.get("commit_hash")
    return scan["_id"] if commit in (None, "") else commit


async def window_scans_by_branch(
    scan_repo: ScanRepository,
    project_ids: Sequence[str],
    since: datetime | None,
) -> dict[str, dict[str, BranchWindowActivity]]:
    """Both read paths pick their branch from these counts, so neither settles on a branch the other would not."""
    # A findings-only scan holds no dependencies to compare; $ne keeps scans older than sbom_refs.
    scoped = {**usable_scan_match(since), "sbom_refs": {"$ne": []}}

    commits: dict[tuple[str, str], Counter[str]] = {}
    latest: dict[tuple[str, str], datetime] = {}
    async for chain, scan in _window_docs(scan_repo.collection, project_ids, scoped, _ACTIVITY_PROJECTION):
        per_commit = commits.setdefault(chain, Counter())
        if isinstance(token := _commit_token(scan), str):
            per_commit[token] += 1
        latest[chain] = max(latest.get(chain, scan["created_at"]), scan["created_at"])

    activity: dict[str, dict[str, BranchWindowActivity]] = {}
    for (project_id, branch), per_commit in commits.items():
        activity.setdefault(project_id, {})[branch] = BranchWindowActivity(per_commit, latest[project_id, branch])
    return activity


async def window_scan_ids_by_branch(
    scan_repo: ScanRepository,
    project_ids: Sequence[str],
    since: datetime,
) -> dict[tuple[str, str], list[tuple[str, datetime]]]:
    """Per scan, as the writer owes each scan a delta; a non-date created_at drops out here as in the writer."""
    scoped = usable_scan_match(since)
    scans: dict[tuple[str, str], list[tuple[str, datetime]]] = {}
    async for chain, scan in _window_docs(scan_repo.collection, project_ids, scoped, _SCAN_ID_PROJECTION):
        scans.setdefault(chain, []).append((scan["_id"], scan["created_at"]))
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
        scope = {"scan_created_at": {"$gte": since}, "schema_version": UPDATE_DELTA_SCHEMA_VERSION}
        buckets: dict[str, dict[str, list[dict[str, Any]]]] = {}
        async for (project_id, branch), delta in _window_docs(self.collection, project_ids, scope, _WINDOW_PROJECTION):
            buckets.setdefault(project_id, {}).setdefault(branch, []).append(delta)
        for branches in buckets.values():
            for deltas in branches.values():
                deltas.sort(key=_chain_order)
        return buckets

    async def window_ledger_by_branch(
        self, project_ids: Sequence[str], since: datetime
    ) -> dict[tuple[str, str], dict[str, LedgerEntry]]:
        """Only chain fields travel; whole deltas would make the nightly census as heavy as the comparison's fold."""
        chains: dict[tuple[str, str], dict[str, LedgerEntry]] = {}
        scope = {"scan_created_at": {"$gte": since}}
        async for chain, delta in _window_docs(self.collection, project_ids, scope, _LEDGER_PROJECTION):
            chains.setdefault(chain, {})[delta["_id"]] = _ledger_entry(delta)
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
