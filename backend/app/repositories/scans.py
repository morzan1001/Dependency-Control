"""Repository for scans, and the one rule for what a project's head is.

Head is the freshest readable analysis of the tip build of the project's head branch.

The head branch is the default branch while the VCS still has one and it holds a usable scan, else
any branch it has not deleted. The tip build is the newest build there: a rescan carries
``created_at = now`` over an older commit and a tag pipeline writes its tag into ``branch``, so a
branch build outranks a tag build and both outrank a rescan; any scan with an SBOM outranks every
scan without one. The freshest analysis is the newest usable scan in that build's rescan lineage.
``latest_scan_id`` caches the answer and is trusted only while it names a readable scan that may
head the project.

The same two steps answer per branch (``branch_tips``) and per release (``freshest_in_lineage`` on
the marked scan), so the project tile, head-mode analytics and the release view cannot disagree.
"""

import asyncio
import logging
from collections.abc import AsyncGenerator, Awaitable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, NamedTuple

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
from app.schemas.projections import ScanMinimal, ScanWithStats

logger = logging.getLogger(__name__)

# $ne rather than False: scans predating the flag carry none and are builds.
USABLE_BUILD_MATCH: dict[str, Any] = {"status": {"$in": SCAN_USABLE_STATUSES}, "is_rescan": {"$ne": True}}
# A tag pipeline writes its tag into branch, so such a scan names no branch.
BRANCH_SCAN_FILTER: dict[str, Any] = {"$expr": {"$ne": ["$branch", "$commit_tag"]}}
# A scan without an SBOM (SAST only) carries no dependencies, so it heads only where no scan has one.
HAS_SBOM_MATCH: dict[str, Any] = {"sbom_refs": {"$exists": True, "$ne": []}}
# Best first, so a project whose usable scans are all tag builds or rescans still has a tip.
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


def is_usable_build(doc: dict[str, Any]) -> bool:
    return doc.get("status") in SCAN_USABLE_STATUSES and not doc.get("is_rescan")


@dataclass(frozen=True)
class LineageAnalysis:
    """The analysis a scan's rescan lineage resolves to, and whether the walk that found it ran out."""

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
    "is_rescan": 1,
    "original_scan_id": 1,
    "status": 1,
    "reachability_pending": 1,
    "project_id": 1,
}


def _project_id_and_deleted(project: Any) -> tuple[str | None, list[str]]:
    """Extract ``(project_id, deleted_branches)`` from a Project model or raw dict."""
    if isinstance(project, dict):
        pid = project.get("_id") or project.get("id")
        deleted = project.get("deleted_branches") or []
    else:
        pid = getattr(project, "id", None) or getattr(project, "_id", None)
        deleted = getattr(project, "deleted_branches", None) or []
    return pid, list(deleted)


def _project_field(project: Any, name: str) -> Any:
    if isinstance(project, dict):
        return project.get(name)
    return getattr(project, name, None)


class _HeadScope(NamedTuple):
    """Everything head resolution reads off one project."""

    default_branch: str | None
    deleted: list[str]
    pointer: str | None


def _head_scope(project: Any, deleted_override: list[str] | None = None) -> tuple[str | None, _HeadScope]:
    project_id, deleted = _project_id_and_deleted(project)
    return project_id, _HeadScope(
        default_branch=_project_field(project, "default_branch"),
        deleted=deleted if deleted_override is None else list(deleted_override),
        pointer=_project_field(project, "latest_scan_id"),
    )


def _live_default(scope: _HeadScope) -> str | None:
    return scope.default_branch if scope.default_branch and scope.default_branch not in scope.deleted else None


def _may_head(doc: dict[str, Any], scope: _HeadScope) -> bool:
    """Whether this scan may stand in for the project's tip build without re-deriving it.

    With a live default branch only a scan on it may; otherwise any branch may, but a tag build only
    ranks behind every branch build, so the derived pick has to decide.
    """
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

    async def update(self, scan_id: str, update_data: dict[str, Any]) -> Scan | None:
        await self.collection.update_one({"_id": scan_id}, {"$set": update_data})
        return await self.get_by_id(scan_id)

    async def update_raw(self, scan_id: str, update_ops: dict[str, Any]) -> None:
        await self.collection.update_one({"_id": scan_id}, update_ops)

    async def claim_pending(self, scan_id: str, worker_id: str) -> dict[str, Any] | None:
        """Hand a pending scan to one worker; None when another worker took it first."""
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
        """Fail a scan only while it is still in ``status`` and, given one, still held by ``worker_id``,
        so a stale writer cannot fail a run housekeeping reset and another worker claimed."""
        query: dict[str, Any] = {"_id": scan_id, "status": status}
        if worker_id:
            query["worker_id"] = worker_id
        result = await self.collection.update_one(query, {"$set": {"status": SCAN_STATUS_FAILED, "error": error}})
        return bool(result.modified_count)

    async def requeue(self, scan_id: str) -> bool:
        """Send a processing scan back to pending for another attempt, releasing its worker."""
        result = await self.collection.update_one(
            {"_id": scan_id, "status": SCAN_STATUS_PROCESSING},
            {
                "$set": {"status": SCAN_STATUS_PENDING, "worker_id": None, "analysis_started_at": None},
                "$inc": {"retry_count": 1},
            },
        )
        return bool(result.modified_count)

    async def reopen_finished(self, scan_id: str) -> bool:
        """Send a finished scan back to pending because new input arrived for it."""
        result = await self.collection.update_one(
            {"_id": scan_id, "status": {"$in": SCAN_USABLE_STATUSES}},
            {"$set": {"status": SCAN_STATUS_PENDING, "retry_count": 0}},
        )
        return bool(result.modified_count)

    async def delete(self, scan_id: str) -> bool:
        result = await self.collection.delete_one({"_id": scan_id})
        return result.deleted_count > 0

    async def delete_many(self, query: dict[str, Any]) -> int:
        result = await self.collection.delete_many(query)
        return result.deleted_count

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
        projection: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        cursor = (
            self.collection.find({"project_id": project_id}, projection)
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(limit)

    async def find_one(self, query: dict[str, Any], sort: list[tuple] | None = None) -> dict[str, Any] | None:
        if sort:
            return await self.collection.find_one(query, sort=sort)
        return await self.collection.find_one(query)

    async def _tip(self, match: dict[str, Any], projection: dict[str, int] | None = _TIP_PROJECTION) -> dict | None:
        """The newest scan under ``match`` in the best tier that holds one; each tier is one index seek."""
        for tier in _TIP_TIERS:
            doc: dict | None = await self.collection.find_one({**match, **tier}, projection, sort=SCANS_TIP_SORT)
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

    async def head_build(self, project: Any, match: dict[str, Any]) -> dict | None:
        """The whole document of the build that heads the project among scans under ``match``,
        before the lineage step."""
        project_id, scope = _head_scope(project)
        return await self._head_build(project_id, scope, match, None) if project_id else None

    async def branch_tip(self, project_id: str, branch: str) -> Scan | None:
        """The head rule scoped to one branch: its tip build, resolved to the freshest analysis of it."""
        tip = await self._tip({"project_id": project_id, "branch": branch})
        doc = (await self._freshest_analysis_docs([tip])).get(tip["_id"]) if tip else None
        return Scan(**doc) if doc else None

    async def branch_tips(
        self, project_id: str, deleted_branches: list[str] | None = None
    ) -> list[tuple[str, int, dict[str, Any] | None]]:
        """``(branch, scan_count, tip)`` per branch the project has not deleted, sorted by branch.

        The tip is ``branch_tip``'s answer, and ``scan_count`` counts the branch's builds over every
        scan it holds, so neither depends on a page of the scan list.
        """
        match: dict[str, Any] = {"project_id": project_id, **BRANCH_SCAN_FILTER}
        if deleted_branches:
            match["branch"] = {"$nin": list(deleted_branches)}
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
        # Callers derive the limit from the id list they are asking about, and Mongo reads
        # limit(0) as unbounded, so an empty list has to answer before the query is built.
        if limit <= 0:
            return []
        cursor = self.collection.find(query, {"_id": 1, "stats": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ScanWithStats(**doc) for doc in docs]

    async def count(self, query: dict[str, Any] | None = None, limit: int | None = None) -> int:
        if limit is not None:
            return await self.collection.count_documents(query or {}, limit=limit)
        return await self.collection.count_documents(query or {})

    async def get_latest_active_scan(self, project: Any) -> Scan | None:
        """The project's head as a full document; ``project`` may be a model or a raw dict."""
        project_id, scope = _head_scope(project)
        if not project_id:
            return None
        scan_id = (await self._head_scan_ids({project_id: scope})).get(project_id)
        return await self.get_by_id(scan_id) if scan_id else None

    async def head_fields(self, project: Any, deleted_branches: list[str] | None = None) -> dict[str, Any]:
        """``latest_scan_id`` and ``stats`` for the project document, derived afresh rather than
        through the pointer they replace. ``deleted_branches`` overrides a set not yet persisted."""
        project_id, scope = _head_scope(project, deleted_branches)
        scan_id = None
        if project_id:
            scan_id = (await self._head_scan_ids({project_id: scope._replace(pointer=None)})).get(project_id)
        doc = await self.collection.find_one({"_id": scan_id}, {"stats": 1}) if scan_id else None
        return {"latest_scan_id": doc["_id"] if doc else None, "stats": doc.get("stats") if doc else None}

    async def get_preceding_scan(self, scan_id: str) -> Scan | None:
        """The build the given scan's commit succeeded: the newest usable build on its branch that
        predates it. A rescan carries today's date over an older commit, so a rescan is measured by
        the build it re-analysed and never counts as a predecessor."""
        fields = {"project_id": 1, "branch": 1, "created_at": 1, "is_rescan": 1, "original_scan_id": 1}
        current = await self.collection.find_one({"_id": scan_id}, fields)
        if current and current.get("is_rescan") and current.get("original_scan_id"):
            current = await self.collection.find_one({"_id": current["original_scan_id"]}, fields)
        if not current or current.get("created_at") is None:
            return None
        query = {
            **USABLE_BUILD_MATCH,
            "project_id": current.get("project_id"),
            "branch": current.get("branch"),
            "created_at": {"$lt": current["created_at"]},
        }
        data = await self.collection.find_one(query, sort=SCANS_TIP_SORT)
        return Scan(**data) if data else None

    async def freshest_in_lineage(
        self, scan_ids: Iterable[str], seeds: dict[str, dict[str, Any]] | None = None
    ) -> dict[str, LineageAnalysis]:
        """The freshest readable analysis of each of these scans, following its rescan chain.

        Both rescan creators root a rescan at its lineage root, and the root's ``latest_rescan_id``
        moves only onto a rescan that finished usable, so a chain is normally one link deep. Bounded,
        so a cyclic pointer cannot hang a request; a scan whose chain was still going at the bound is
        marked. A scan with no usable analysis in its chain is absent rather than a misleading id.
        ``seeds`` are scans the caller already read with the chain fields, spared a second read.
        """
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
        """The date of the oldest of these scans: how far back the answer they carry reaches.

        Release mode resolves to a build that was deliberately not rebuilt, so its findings are the
        vulnerability landscape of that date and not of today; a reader given the number without
        the date reads it as current.
        """
        if not scan_ids:
            return None
        doc = await self.collection.find_one(
            {"_id": {"$in": list(scan_ids)}}, {"created_at": 1}, sort=[("created_at", 1)]
        )
        return doc.get("created_at") if doc else None

    async def _freshest_analysis_docs(self, tips: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Each of these tip builds' ids mapped to the whole document of the analysis its lineage resolves to."""
        if not tips:
            return {}
        resolved = await self.freshest_in_lineage([tip["_id"] for tip in tips], seeds={tip["_id"]: tip for tip in tips})
        docs = {
            doc["_id"]: doc
            async for doc in self.collection.find({"_id": {"$in": sorted({a.scan_id for a in resolved.values()})}})
        }
        return {scan_id: docs[analysis.scan_id] for scan_id, analysis in resolved.items() if analysis.scan_id in docs}

    async def get_latest_active_scan_ids(self, projects: list[Any]) -> dict[str, str]:
        """Maps project_id -> the scan that represents its head, under this module's head rule;
        projects resolving to no scan are omitted.
        """
        scopes: dict[str, _HeadScope] = {}
        for project in projects:
            project_id, scope = _head_scope(project)
            if project_id:
                scopes[project_id] = scope
        return await self._head_scan_ids(scopes)

    async def _head_scan_ids(self, scopes: dict[str, _HeadScope]) -> dict[str, str]:
        """The one head resolver: pick each project's tip build, then report the freshest analysis of
        it. ``latest_scan_id`` stands in for the pick while it names a readable scan that may head the
        project; it names whichever analysis was last cached, so it goes through the lineage step too."""
        pointers = {pid: scope.pointer for pid, scope in scopes.items() if scope.pointer}
        readable: dict[str, dict[str, Any]] = {}
        if pointers:
            # Retention deletes a scan without clearing the pointer, and re-ingest or a late analyzer
            # result sends a completed scan back to pending.
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
