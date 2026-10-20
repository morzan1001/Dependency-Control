"""Head rule: the freshest analysis of the live default branch's tip build, else of any live branch's."""

import asyncio
import logging
from collections.abc import AsyncGenerator, Awaitable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, NamedTuple

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReturnDocument

from app.core import UNDATED
from app.core.constants import (
    MAX_RESCAN_HOPS,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    SCAN_USABLE_STATUSES,
    SCANS_TIP_SORT,
    ScanStatus,
)
from app.models.project import Scan
from app.models.stats import Stats
from app.schemas.projections import ScanMinimal, ScanWithStats

logger = logging.getLogger(__name__)

# None counts too, as older scans lack the flag; $in, unlike $ne, lets the index skip rescans instead of fetching them.
USABLE_BUILD_MATCH: dict[str, Any] = {"status": {"$in": SCAN_USABLE_STATUSES}, "is_rescan": {"$in": [False, None]}}
# A tag pipeline writes its tag into branch, so such a scan names no branch.
BRANCH_SCAN_FILTER: dict[str, Any] = {"$expr": {"$ne": ["$branch", "$commit_tag"]}}
# A scan without an SBOM (SAST only) carries no dependencies, so it heads only where no scan has one.
# The scans_sbom_branch_tip index filters on this exact predicate, which a query must repeat.
HAS_SBOM_MATCH: dict[str, Any] = {"sbom_refs.0": {"$exists": True}}
# Builds with a non-empty tag; the scans_tag_builds index filters on this exact predicate, which a query must repeat.
TAG_BUILD_MATCH: dict[str, Any] = {"commit_tag": {"$gt": ""}}
# Best first: a rescan, dated today over an older commit, ranks last, yet still heads a project with nothing else.
_TIP_TIERS: tuple[dict[str, Any], ...] = tuple(
    {**sbom, **tier}
    for sbom in (HAS_SBOM_MATCH, {})
    for tier in (
        {**USABLE_BUILD_MATCH, **BRANCH_SCAN_FILTER},
        USABLE_BUILD_MATCH,
        {"status": {"$in": SCAN_USABLE_STATUSES}},
    )
)
_TIP_LOOKUP_CONCURRENCY = 16
_CHAIN_PROJECTION = {"_id": 1, "latest_rescan_id": 1, "status": 1, "created_at": 1}
_TIP_PROJECTION = {**_CHAIN_PROJECTION, "branch": 1, "commit_tag": 1}
_HEAD_SCOPE_PROJECTION = {"default_branch": 1, "deleted_branches": 1, "latest_scan_id": 1}
_HEAD_SYNC_ATTEMPTS = 3


def is_usable_build(doc: dict[str, Any]) -> bool:
    return doc.get("status") in SCAN_USABLE_STATUSES and not doc.get("is_rescan")


@dataclass(frozen=True)
class LineageAnalysis:
    scan_id: str
    # True when the chain still had links at MAX_RESCAN_HOPS, so a fresher analysis may exist.
    chain_bounded: bool


def _created_at(doc: dict[str, Any]) -> datetime:
    # A scan with no created_at sorts oldest, so it wins only when its chain holds nothing else.
    return doc.get("created_at") or UNDATED


def _is_fresher(doc: dict[str, Any], incumbent: dict[str, Any]) -> bool:
    """SCANS_TIP_SORT in Python: newer wins, and on a same-millisecond tie the lower _id does."""
    doc_at, incumbent_at = _created_at(doc), _created_at(incumbent)
    if doc_at != incumbent_at:
        return doc_at > incumbent_at
    return str(doc["_id"]) < str(incumbent["_id"])


async def _bounded_gather[T](awaitables: Iterable[Awaitable[T]]) -> list[T]:
    semaphore = asyncio.Semaphore(_TIP_LOOKUP_CONCURRENCY)

    async def run(awaitable: Awaitable[T]) -> T:
        async with semaphore:
            return await awaitable

    return await asyncio.gather(*(run(awaitable) for awaitable in awaitables))


_MINIMAL_PROJECTION = {
    "_id": 1,
    "pipeline_id": 1,
    "original_scan_id": 1,
    "reachability_pending": 1,
    "project_id": 1,
    "branch": 1,
}


def _project_field(project: Any, name: str) -> Any:
    if isinstance(project, dict):
        return project.get(name)
    return getattr(project, name, None)


class _HeadScope(NamedTuple):
    default_branch: str | None
    deleted: list[str]
    pointer: str | None


def _head_scope(project: Any) -> tuple[str | None, _HeadScope]:
    return _project_field(project, "_id" if isinstance(project, dict) else "id"), _HeadScope(
        default_branch=_project_field(project, "default_branch"),
        deleted=list(_project_field(project, "deleted_branches") or []),
        pointer=_project_field(project, "latest_scan_id"),
    )


def _live_default(scope: _HeadScope) -> str | None:
    return scope.default_branch if scope.default_branch and scope.default_branch not in scope.deleted else None


def _may_head(doc: dict[str, Any], scope: _HeadScope) -> bool:
    default = _live_default(scope)
    if default:
        return doc.get("branch") == default
    return doc.get("branch") not in scope.deleted and doc.get("branch") != doc.get("commit_tag")


class ScanRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.scans

    async def get_by_id(self, scan_id: str) -> Scan | None:
        data = await self.collection.find_one({"_id": scan_id})
        return Scan(**data) if data else None

    async def get_minimal_by_id(self, scan_id: str) -> ScanMinimal | None:
        data = await self.collection.find_one({"_id": scan_id}, _MINIMAL_PROJECTION)
        return ScanMinimal(**data) if data else None

    async def create(self, scan: Scan) -> Scan:
        await self.collection.insert_one(scan.model_dump(by_alias=True))
        return scan

    async def upsert(self, query: dict[str, Any], update: dict[str, Any]) -> None:
        await self.collection.update_one(query, update, upsert=True)

    async def touch(self, scan_id: str) -> None:
        await self.collection.update_one({"_id": scan_id}, {"$set": {"updated_at": datetime.now(timezone.utc)}})

    async def update_raw(self, scan_id: str, update_ops: dict[str, Any], guard: dict[str, Any] | None = None) -> bool:
        result = await self.collection.update_one({"_id": scan_id, **(guard or {})}, update_ops)
        return bool(result.matched_count)

    async def set_stats(self, scan_id: str, stats: Stats, extra: dict[str, Any] | None = None) -> None:
        """Also rewrites the copy in each latest_run reporting it: its own and its root's."""
        dumped = stats.model_dump()
        scan = await self.collection.find_one_and_update(
            {"_id": scan_id}, {"$set": {"stats": dumped, **(extra or {})}}, projection={"original_scan_id": 1}
        )
        root_id = (scan or {}).get("original_scan_id") or scan_id
        await self.collection.update_many(
            {"_id": {"$in": [scan_id, root_id]}, "latest_run.scan_id": scan_id}, {"$set": {"latest_run.stats": dumped}}
        )

    async def claim_pending(self, scan_id: str, worker_id: str) -> dict[str, Any] | None:
        claimed: dict[str, Any] | None = await self.collection.find_one_and_update(
            {"_id": scan_id, "status": SCAN_STATUS_PENDING},
            {
                "$set": {
                    "status": SCAN_STATUS_PROCESSING,
                    "worker_id": worker_id,
                    "analysis_started_at": datetime.now(timezone.utc),
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return claimed

    async def mark_failed(
        self, scan_id: str, error: str, *, status: ScanStatus = SCAN_STATUS_PROCESSING, worker_id: str | None = None
    ) -> bool:
        """Guarded on status and worker, so a stale writer cannot fail a run that another worker has since claimed."""
        query: dict[str, Any] = {"_id": scan_id, "status": status}
        if worker_id:
            query["worker_id"] = worker_id
        now = datetime.now(timezone.utc)
        run = {"scan_id": scan_id, "status": SCAN_STATUS_FAILED, "completed_at": now}
        failed = await self.collection.find_one_and_update(
            query,
            {"$set": {"status": SCAN_STATUS_FAILED, "error": error, "completed_at": now, "latest_run": run}},
            projection={"original_scan_id": 1, "sbom_generation": 1},
        )
        if failed and failed.get("original_scan_id"):
            await self.report_rescan_run(failed["original_scan_id"], failed.get("sbom_generation"), {"latest_run": run})
        return failed is not None

    async def report_rescan_run(self, root_id: str, sbom_generation: int | None, fields: dict[str, Any]) -> None:
        """Skipped once the build was re-ingested past the SBOM the rescan analysed."""
        await self.collection.update_one({"_id": root_id, "sbom_generation": sbom_generation}, {"$set": fields})

    async def requeue(
        self, scan_id: str, worker_id: str | None, *, counter: Literal["retry_count", "stuck_retry_count"]
    ) -> bool:
        result = await self.collection.update_one(
            {"_id": scan_id, "status": SCAN_STATUS_PROCESSING, "worker_id": worker_id},
            {
                "$set": {"status": SCAN_STATUS_PENDING, "worker_id": None, "analysis_started_at": None},
                "$inc": {counter: 1},
            },
        )
        return bool(result.modified_count)

    async def renew_claim(self, scan_id: str, worker_id: str) -> bool:
        result = await self.collection.update_one(
            {"_id": scan_id, "status": SCAN_STATUS_PROCESSING, "worker_id": worker_id},
            {"$set": {"analysis_started_at": datetime.now(timezone.utc)}},
        )
        return bool(result.matched_count)

    async def reopen_finished(self, scan_id: str, *, statuses: Sequence[ScanStatus] = SCAN_USABLE_STATUSES) -> bool:
        result = await self.collection.update_one(
            {"_id": scan_id, "status": {"$in": statuses}},
            {"$set": {"status": SCAN_STATUS_PENDING, "retry_count": 0, "stuck_retry_count": 0}},
        )
        return bool(result.modified_count)

    async def find_one(
        self, query: dict[str, Any], sort: list[tuple] | None = None, projection: dict[str, int] | None = None
    ) -> dict[str, Any] | None:
        if sort:
            return await self.collection.find_one(query, projection, sort=sort)
        return await self.collection.find_one(query, projection)

    async def _tip(self, match: dict[str, Any], projection: dict[str, int] | None = _TIP_PROJECTION) -> dict | None:
        """A match that folds tiers into one query, as the rescan scheduler's does, runs that query once."""
        tried: list[dict[str, Any]] = []
        for tier in _TIP_TIERS:
            query = {**match, **tier}
            if query in tried:
                continue
            tried.append(query)
            doc: dict | None = await self.collection.find_one(query, projection, sort=SCANS_TIP_SORT)
            if doc:
                return doc
        return None

    async def _head_build(
        self, project_id: str, scope: _HeadScope, match: dict[str, Any], projection: dict[str, int] | None
    ) -> dict | None:
        base = {**match, "project_id": project_id}
        default = _live_default(scope)
        if default and (on_default := await self._tip({**base, "branch": default}, projection)):
            return on_default
        # A default branch this instance never scanned must leave the project visible rather than empty.
        if scope.deleted:
            base["branch"] = {"$nin": scope.deleted}
        return await self._tip(base, projection)

    async def head_build(self, project: Any, match: dict[str, Any], projection: dict[str, int]) -> dict | None:
        """The heading build itself, before the lineage step."""
        project_id, scope = _head_scope(project)
        return await self._head_build(project_id, scope, match, projection) if project_id else None

    async def branch_tip(self, project_id: str, branch: str) -> Scan | None:
        tip = await self._tip({"project_id": project_id, "branch": branch})
        doc = (await self._freshest_analysis_docs([tip])).get(tip["_id"]) if tip else None
        return Scan(**doc) if doc else None

    async def branch_last_scans(self, project_id: str) -> dict[str, datetime]:
        """Newest scan date per branch name, grouped off the index alone; one read per name drops names only tags carry."""
        rows = await self.aggregate(
            [
                {"$match": {"project_id": project_id}},
                {"$group": {"_id": "$branch", "last_scan_at": {"$max": "$created_at"}}},
            ]
        )
        last = {row["_id"]: row["last_scan_at"] for row in rows if isinstance(row["_id"], str) and row["_id"]}
        branch_scans = {"project_id": project_id, **BRANCH_SCAN_FILTER}
        found = await _bounded_gather(self.collection.find_one({**branch_scans, "branch": b}, {"_id": 1}) for b in last)
        return {branch: at for (branch, at), hit in zip(last.items(), found, strict=True) if hit}

    async def branch_tips(
        self, project_id: str, deleted_branches: list[str] | None = None, since: datetime | None = None
    ) -> list[tuple[str, int, dict[str, Any] | None]]:
        """(branch, build count, branch_tip's answer) per live branch; ``since`` counts only the scans since then."""
        match: dict[str, Any] = {"project_id": project_id, **BRANCH_SCAN_FILTER}
        if deleted_branches:
            match["branch"] = {"$nin": list(deleted_branches)}
        if since is not None:
            match["created_at"] = {"$gte": since}
        rows = await self.aggregate(
            [
                {"$match": match},
                {
                    "$group": {
                        "_id": "$branch",
                        "scan_count": {"$sum": {"$cond": [{"$eq": ["$is_rescan", True]}, 0, 1]}},
                    }
                },
            ]
        )
        counts = {row["_id"]: int(row["scan_count"]) for row in rows if isinstance(row["_id"], str) and row["_id"]}
        branches = sorted(counts)
        builds = await _bounded_gather(self._tip({"project_id": project_id, "branch": b}) for b in branches)
        analyses = await self._freshest_analysis_docs([build for build in builds if build])
        return [
            (branch, counts[branch], analyses.get(build["_id"]) if build else None)
            for branch, build in zip(branches, builds, strict=True)
        ]

    async def find_many(
        self,
        query: dict[str, Any],
        sort: list[tuple] | None = None,
        skip: int = 0,
        limit: int | None = None,
    ) -> list[Scan]:
        docs = await self.find_many_raw(query, sort=sort, skip=skip, limit=limit)
        return [Scan(**doc) for doc in docs]

    async def find_many_raw(
        self,
        query: dict[str, Any],
        sort: list[tuple] | None = None,
        skip: int = 0,
        limit: int | None = None,
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        if limit is not None and limit <= 0:
            return []
        cursor = self.collection.find(query, projection)
        if sort:
            cursor = cursor.sort(sort)
        if skip:
            cursor = cursor.skip(skip)
        if limit is not None:
            cursor = cursor.limit(limit)
        return await cursor.to_list(limit)

    async def find_many_with_stats(
        self,
        query: dict[str, Any],
        limit: int,
    ) -> list[ScanWithStats]:
        # Mongo reads limit(0) as unbounded, and the limit is the length of an id list that may be empty.
        if limit <= 0:
            return []
        cursor = self.collection.find(query, {"_id": 1, "stats": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ScanWithStats(**doc) for doc in docs]

    async def count(self, query: dict[str, Any] | None = None, limit: int | None = None) -> int:
        if limit is not None:
            return await self.collection.count_documents(query or {}, limit=limit)
        return await self.collection.count_documents(query or {})

    async def get_latest_active_scan_id(self, project: Any) -> str | None:
        project_id, scope = _head_scope(project)
        if not project_id:
            return None
        return (await self._head_scan_ids({project_id: scope})).get(project_id)

    async def get_latest_active_scan(self, project: Any) -> Scan | None:
        scan_id = await self.get_latest_active_scan_id(project)
        return await self.get_by_id(scan_id) if scan_id else None

    async def belongs_to_project(self, scan_ids: set[str], project_id: str) -> bool:
        return (
            await self.count({"_id": {"$in": list(scan_ids)}, "project_id": project_id}, limit=len(scan_ids))
        ) == len(scan_ids)

    async def sync_project_head(self, project_id: str) -> str | None:
        """latest_scan_id's only writer, guarded on the pointer it replaces; None if no head could be written."""
        for _ in range(_HEAD_SYNC_ATTEMPTS):
            project = await self.db.projects.find_one({"_id": project_id}, _HEAD_SCOPE_PROJECTION)
            if not project:
                return None
            _, scope = _head_scope(project)
            scan_id = (await self._head_scan_ids({project_id: scope._replace(pointer=None)})).get(project_id)
            doc = await self.collection.find_one({"_id": scan_id}, {"stats": 1}) if scan_id else None
            head = doc["_id"] if doc else None
            # A pointer moved in between belongs to a writer that saw newer scans, so the head is derived again.
            written = await self.db.projects.update_one(
                {"_id": project_id, "latest_scan_id": scope.pointer},
                {"$set": {"latest_scan_id": head, "stats": doc.get("stats") if doc else None}},
            )
            if written.matched_count:
                return head
        return None

    async def get_preceding_scans(self, scan_id: str, limit: int) -> list[Scan]:
        """A rescan is measured by the build it re-analysed, as it carries today's date over an older commit."""
        fields = {"project_id": 1, "branch": 1, "commit_tag": 1, "created_at": 1, "is_rescan": 1, "original_scan_id": 1}
        current = await self.collection.find_one({"_id": scan_id}, fields)
        if current and current.get("is_rescan") and current.get("original_scan_id"):
            current = await self.collection.find_one({"_id": current["original_scan_id"]}, fields)
        if not current or current.get("created_at") is None:
            return []
        branch, tag = current.get("branch"), current.get("commit_tag")
        line = TAG_BUILD_MATCH if tag and tag == branch else {"branch": branch}
        query = {
            **USABLE_BUILD_MATCH,
            "project_id": current.get("project_id"),
            **line,
            "created_at": {"$lt": current["created_at"]},
        }
        return await self.find_many(query, sort=SCANS_TIP_SORT, limit=limit)

    async def freshest_in_lineage(
        self, scan_ids: Iterable[str], seeds: dict[str, dict[str, Any]] | None = None
    ) -> dict[str, LineageAnalysis]:
        """``seeds`` are scans already read with the chain fields; a chain without a readable analysis is left out."""
        frontier: dict[str, str] = {scan_id: scan_id for scan_id in scan_ids}
        seeded = seeds or {}
        visited: set[str] = set()
        freshest: dict[str, dict[str, Any]] = {}
        bounded: set[str] = set()

        for _hop in range(MAX_RESCAN_HOPS + 1):
            if not frontier:
                break
            visited.update(frontier)
            next_frontier: dict[str, str] = {}
            docs = [seeded[scan_id] for scan_id in frontier if scan_id in seeded]
            unread = [scan_id for scan_id in frontier if scan_id not in seeded]
            if unread:
                docs += await self.collection.find({"_id": {"$in": unread}}, _CHAIN_PROJECTION).to_list(None)
            seeded = {}
            for doc in docs:
                root_id = frontier[doc["_id"]]
                if doc.get("status") in SCAN_USABLE_STATUSES:
                    incumbent = freshest.get(root_id)
                    if incumbent is None or _is_fresher(doc, incumbent):
                        freshest[root_id] = doc
                rescan_id = doc.get("latest_rescan_id")
                if rescan_id and rescan_id not in visited:
                    next_frontier[rescan_id] = root_id
            frontier = next_frontier

        if frontier:
            bounded = set(frontier.values())
            logger.warning(
                "Rescan lineage still had links at the %d-hop bound for %d scan(s); the resolved analysis may be stale",
                MAX_RESCAN_HOPS,
                len(bounded),
            )

        return {
            root_id: LineageAnalysis(scan_id=doc["_id"], chain_bounded=root_id in bounded)
            for root_id, doc in freshest.items()
        }

    async def oldest_analysis_at(self, scan_ids: Sequence[str]) -> datetime | None:
        if not scan_ids:
            return None
        doc = await self.collection.find_one(
            {"_id": {"$in": list(scan_ids)}}, {"created_at": 1}, sort=[("created_at", 1)]
        )
        return doc.get("created_at") if doc else None

    async def _freshest_analysis_docs(self, tips: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        if not tips:
            return {}
        resolved = await self.freshest_in_lineage([tip["_id"] for tip in tips], seeds={tip["_id"]: tip for tip in tips})
        docs = {
            doc["_id"]: doc
            async for doc in self.collection.find({"_id": {"$in": sorted({a.scan_id for a in resolved.values()})}})
        }
        return {scan_id: docs[analysis.scan_id] for scan_id, analysis in resolved.items() if analysis.scan_id in docs}

    async def get_latest_active_scan_ids(self, projects: list[Any]) -> dict[str, str]:
        scopes: dict[str, _HeadScope] = {}
        for project in projects:
            project_id, scope = _head_scope(project)
            if project_id:
                scopes[project_id] = scope
        return await self._head_scan_ids(scopes)

    async def _head_scan_ids(self, scopes: dict[str, _HeadScope]) -> dict[str, str]:
        """A cached latest_scan_id that may still head the project stands in for the pick, lineage step included."""
        pointers = {pid: scope.pointer for pid, scope in scopes.items() if scope.pointer}
        readable: dict[str, dict[str, Any]] = {}
        if pointers:
            # Retention leaves a pointer to a deleted scan, and re-ingest or a late result reopens a completed one.
            cursor = self.collection.find(
                {"_id": {"$in": list(pointers.values())}, "status": {"$in": SCAN_USABLE_STATUSES}}, _TIP_PROJECTION
            )
            readable = {doc["_id"]: doc async for doc in cursor}
        tips = {
            pid: readable[scan_id]
            for pid, scan_id in pointers.items()
            if scan_id in readable and _may_head(readable[scan_id], scopes[pid])
        }
        unresolved = [pid for pid in scopes if pid not in tips]
        derived = await _bounded_gather(self._head_build(pid, scopes[pid], {}, _TIP_PROJECTION) for pid in unresolved)
        tips.update({pid: doc for pid, doc in zip(unresolved, derived, strict=True) if doc})
        lineage = await self.freshest_in_lineage(
            [doc["_id"] for doc in tips.values()], seeds={doc["_id"]: doc for doc in tips.values()}
        )
        return {pid: lineage[doc["_id"]].scan_id for pid, doc in tips.items() if doc["_id"] in lineage}

    async def iterate_raw(
        self, query: dict[str, Any], projection: dict[str, int] | None = None
    ) -> AsyncGenerator[dict[str, Any], None]:
        async for doc in self.collection.find(query, projection):
            yield doc

    async def aggregate(self, pipeline: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
        return await self.collection.aggregate(pipeline).to_list(limit)

    async def distinct(self, field: str, query: dict[str, Any] | None = None) -> list[Any]:
        return await self.collection.distinct(field, query or {})
