"""Repository for scans, and the one rule for what a project's head is.

Head is the freshest readable analysis of the tip commit of the project's head branch.

The head branch is the default branch while the VCS still has one, else any branch it has not
deleted. The tip commit is the newest build on that branch: a rescan carries ``created_at = now``
over an older commit, so builds rank ahead of rescans and only a build can move head onto another
commit. The freshest analysis is the newest usable scan in that build's rescan lineage, so the
rescanner's enrichment is what head reports about the commit the builds chose. ``latest_scan_id``
is that answer cached by ingest, trusted only while it names a readable scan on the head branch.

The same two steps answer per branch (``branch_tips``) and per release (``freshest_in_lineage`` on
the marked scan), so the project tile, the analytics page and the release view cannot disagree.
"""

import logging
from collections.abc import AsyncGenerator, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, NamedTuple

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ReadPreference

from app.core import ensure_utc
from app.core.constants import MAX_RESCAN_HOPS, SCAN_USABLE_STATUSES
from app.core.metrics import track_db_operation
from app.models.project import Scan
from app.schemas.projections import ScanMinimal, ScanWithStats

logger = logging.getLogger(__name__)

_COL = "scans"
_RESCAN_RANK = "_rescan_rank"
_USABLE_RANK = "_usable_rank"
_CHAIN_PROJECTION = {"_id": 1, "latest_rescan_id": 1, "status": 1, "created_at": 1}
_UNDATED = datetime.min.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class LineageAnalysis:
    """The analysis a scan's rescan lineage resolves to, and whether the walk that found it ran out."""

    scan_id: str
    # True when the chain still had links at MAX_RESCAN_HOPS, so a fresher analysis may exist.
    chain_bounded: bool


def _created_at(doc: dict[str, Any]) -> datetime:
    # A scan with no created_at sorts oldest, so it wins only when its chain holds nothing else.
    return ensure_utc(doc.get("created_at")) or _UNDATED


def _is_fresher(doc: dict[str, Any], incumbent: dict[str, Any]) -> bool:
    """Newer wins; on a tie the lower _id does, because BSON dates are milliseconds and two links
    stamped inside one cannot be told apart by their date alone."""
    doc_at, incumbent_at = _created_at(doc), _created_at(incumbent)
    if doc_at != incumbent_at:
        return doc_at > incumbent_at
    return str(doc["_id"]) < str(incumbent["_id"])

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


def _is_head_branch(branch: str | None, default_branch: str | None, deleted: list[str]) -> bool:
    """Whether a scan on this branch can be the project's head.

    The head is the tip of the default branch whenever the VCS still has one, because a pipeline on
    any other branch answers a different question than "what is on main".
    """
    if default_branch and default_branch not in deleted:
        return branch == default_branch
    return branch not in deleted


def _head_pipeline(or_conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"$match": {"$or": or_conditions}},
        # A rescan carries created_at = now while re-analysing an older commit, so it is the tip
        # only once the branch holds nothing that was actually built.
        {"$addFields": {_RESCAN_RANK: {"$cond": [{"$eq": ["$is_rescan", True]}, 1, 0]}}},
        # BSON dates are milliseconds: without _id, two scans stamped inside one leave the
        # project's representative scan up to the server and it can change between requests.
        {"$sort": {_RESCAN_RANK: 1, "created_at": -1, "_id": 1}},
        {"$group": {"_id": "$project_id", "scan_id": {"$first": "$_id"}}},
    ]


def _branch_tip_pipeline(match: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"$match": match},
        {
            "$addFields": {
                _RESCAN_RANK: {"$cond": [{"$eq": ["$is_rescan", True]}, 1, 0]},
                _USABLE_RANK: {"$cond": [{"$in": ["$status", SCAN_USABLE_STATUSES]}, 1, 0]},
            }
        },
        # Unusable scans sort last so they cannot become the tip, while still entering the count.
        {"$sort": {_USABLE_RANK: -1, _RESCAN_RANK: 1, "created_at": -1, "_id": 1}},
        {
            "$group": {
                "_id": "$branch",
                "tip": {"$first": "$$ROOT"},
                "scan_count": {"$sum": {"$cond": [{"$eq": ["$is_rescan", True]}, 0, 1]}},
            }
        },
    ]


class ScanRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.scans

    def _primary(self) -> AsyncIOMotorCollection:
        return self.collection.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]

    async def get_by_id(self, scan_id: str) -> Scan | None:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": scan_id})
        return Scan(**data) if data else None

    async def get_by_id_strong(self, scan_id: str) -> Scan | None:
        with track_db_operation(_COL, "find_one"):
            data = await self._primary().find_one({"_id": scan_id})
        return Scan(**data) if data else None

    async def get_minimal_by_id(self, scan_id: str) -> ScanMinimal | None:
        data = await self.collection.find_one({"_id": scan_id}, _MINIMAL_PROJECTION)
        return ScanMinimal(**data) if data else None

    async def get_minimal_by_id_strong(self, scan_id: str) -> ScanMinimal | None:
        data = await self._primary().find_one({"_id": scan_id}, _MINIMAL_PROJECTION)
        return ScanMinimal(**data) if data else None

    async def create(self, scan: Scan) -> Scan:
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(scan.model_dump(by_alias=True))
        return scan

    async def upsert(self, query: dict[str, Any], update: dict[str, Any]) -> None:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one(query, update, upsert=True)

    async def update(self, scan_id: str, update_data: dict[str, Any]) -> Scan | None:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one({"_id": scan_id}, {"$set": update_data})
        return await self.get_by_id(scan_id)

    async def update_raw(self, scan_id: str, update_ops: dict[str, Any]) -> None:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one({"_id": scan_id}, update_ops)

    async def delete(self, scan_id: str) -> bool:
        with track_db_operation(_COL, "delete_one"):
            result = await self.collection.delete_one({"_id": scan_id})
        return result.deleted_count > 0

    async def delete_many(self, query: dict[str, Any]) -> int:
        with track_db_operation(_COL, "delete_many"):
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

    async def branch_tips(
        self, project_id: str, deleted_branches: list[str] | None = None
    ) -> list[tuple[str, int, dict[str, Any] | None]]:
        """``(branch, scan_count, tip)`` per branch, over every scan the project holds.

        The tip is the module's head rule scoped to one branch: the branch's newest build,
        resolved to the freshest analysis of it, so the project tile reports the same numbers
        analytics does. The branch count bounds the answer, so a busy branch cannot push another
        branch's tip out of it, and ``scan_count`` is grouped rather than counted off a page.
        """
        match: dict[str, Any] = {"project_id": project_id}
        if deleted_branches:
            match["branch"] = {"$nin": list(deleted_branches)}
        rows = await self.aggregate(_branch_tip_pipeline(match))
        builds: list[tuple[str, int, str | None]] = []
        for row in rows:
            branch = row["_id"]
            if not isinstance(branch, str) or not branch:
                continue
            tip = row.get("tip") or {}
            usable = str(tip["_id"]) if tip.get("status") in SCAN_USABLE_STATUSES else None
            builds.append((branch, int(row.get("scan_count", 0)), usable))

        analyses = await self._freshest_analysis_docs([build for _branch, _count, build in builds if build])
        tips = [(branch, count, analyses.get(build) if build else None) for branch, count, build in builds]
        tips.sort(key=lambda row: row[0])
        return tips

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
        # limit=0 means unbounded in pymongo; floor to 1. None stays unbounded via to_list(None).
        safe_limit: int | None = max(limit, 1) if limit is not None else None
        cursor = self.collection.find(query, projection)
        if sort:
            cursor = cursor.sort(sort)
        if skip:
            cursor = cursor.skip(skip)
        if safe_limit is not None:
            cursor = cursor.limit(safe_limit)
        return await cursor.to_list(safe_limit)

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
        with track_db_operation(_COL, "count"):
            if limit is not None:
                return await self.collection.count_documents(query or {}, limit=limit)
            return await self.collection.count_documents(query or {})

    async def get_latest_active_scan(self, project: Any, deleted_branches: list[str] | None = None) -> Scan | None:
        """The project's head as a full document. ``project`` may be a model or a raw dict, and
        ``deleted_branches`` overrides the project's own set, which housekeeping needs while the
        freshly-computed one is not yet persisted."""
        project_id, scope = _head_scope(project, deleted_branches)
        if not project_id:
            return None
        scan_id = (await self._head_scan_ids({project_id: scope})).get(project_id)
        return await self.get_by_id(scan_id) if scan_id else None

    async def get_preceding_scan(self, scan_id: str) -> Scan | None:
        """The build the given scan succeeded: the newest usable build on its own branch that
        predates it. A rescan carries today's date over an older commit, so it is not the build
        anything followed; ``$ne`` rather than ``False`` because the flag is often simply absent."""
        with track_db_operation(_COL, "find_one"):
            current = await self.collection.find_one({"_id": scan_id}, {"project_id": 1, "branch": 1, "created_at": 1})
        if not current or current.get("created_at") is None:
            return None
        query = {
            "project_id": current.get("project_id"),
            "branch": current.get("branch"),
            "status": {"$in": SCAN_USABLE_STATUSES},
            "is_rescan": {"$ne": True},
            "created_at": {"$lt": current["created_at"]},
        }
        with track_db_operation(_COL, "find_one"):
            # Same _id tie-break as head resolution, so two builds stamped inside one millisecond
            # do not swap places between requests.
            data = await self.collection.find_one(query, sort=[("created_at", -1), ("_id", 1)])
        return Scan(**data) if data else None

    async def _readable_scan_branches(self, scan_ids: list[str]) -> dict[str, str | None]:
        """The branch of each of these scans that still exists with a usable status."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(
                {"_id": {"$in": scan_ids}, "status": {"$in": SCAN_USABLE_STATUSES}}, {"branch": 1}
            )
            return {doc["_id"]: doc.get("branch") async for doc in cursor}

    async def freshest_in_lineage(self, scan_ids: Iterable[str]) -> dict[str, LineageAnalysis]:
        """The freshest readable analysis of each of these scans, following its rescan chain.

        Rescans chain — a rescan is created from an original (``_rescan_targets``), so that
        original's ``latest_rescan_id`` is overwritten rather than extended and never advances past
        the first link — and the walk follows unusable links too, or a failed rescan would hide the
        good one behind it. Bounded, so a cyclic pointer cannot hang a request; a scan whose chain
        was still going at the bound is marked, because the answer is then the freshest within ten
        hops rather than the freshest there is. A scan with no usable analysis in its chain, like
        one whose successor retention deleted, is absent rather than a misleading id.
        """
        frontier: dict[str, str] = {scan_id: scan_id for scan_id in scan_ids}
        visited: set[str] = set()
        freshest: dict[str, dict[str, Any]] = {}
        bounded: set[str] = set()

        for _hop in range(MAX_RESCAN_HOPS + 1):
            if not frontier:
                break
            visited.update(frontier)
            next_frontier: dict[str, str] = {}
            with track_db_operation(_COL, "find"):
                async for doc in self.collection.find({"_id": {"$in": list(frontier)}}, _CHAIN_PROJECTION):
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
                "Rescan lineage still had links at the %d-hop bound for %d scan(s); "
                "the resolved analysis may be stale",
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
        with track_db_operation(_COL, "find_one"):
            doc = await self.collection.find_one(
                {"_id": {"$in": list(scan_ids)}}, {"created_at": 1}, sort=[("created_at", 1)]
            )
        return ensure_utc(doc.get("created_at")) if doc else None

    async def _freshest_analysis_docs(self, scan_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Each of these scans mapped to the whole document of the analysis its lineage resolves to."""
        if not scan_ids:
            return {}
        resolved = await self.freshest_in_lineage(scan_ids)
        with track_db_operation(_COL, "find"):
            docs = {
                doc["_id"]: doc
                async for doc in self.collection.find({"_id": {"$in": sorted({a.scan_id for a in resolved.values()})}})
            }
        return {
            scan_id: docs[analysis.scan_id] for scan_id, analysis in resolved.items() if analysis.scan_id in docs
        }

    async def _newest_head_per_project(self, or_conditions: list[dict[str, Any]]) -> dict[str, str]:
        if not or_conditions:
            return {}
        with track_db_operation(_COL, "aggregate"):
            cursor = self.collection.aggregate(_head_pipeline(or_conditions))
            return {doc["_id"]: doc["scan_id"] async for doc in cursor}

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
        """The one head resolver: pick each project's tip commit, then report the freshest analysis
        of it. ``latest_scan_id`` is head cached by ingest, so it is trusted only while it still
        names a readable scan on the head branch — and it names whichever analysis ingest last
        finished, so it goes through the same lineage step as the derived answer."""
        pointers = {pid: scope.pointer for pid, scope in scopes.items() if scope.pointer}

        result: dict[str, str] = {}
        if pointers:
            # Retention deletes a scan without clearing the pointer, so a pointer can name a scan
            # that is gone while an older one it exempted survives. Re-ingest and a late analyzer
            # result send a completed scan back to pending, so it can also name an unreadable one.
            branches = await self._readable_scan_branches(list(pointers.values()))
            for project_id, scan_id in pointers.items():
                scope = scopes[project_id]
                if scan_id in branches and _is_head_branch(branches[scan_id], scope.default_branch, scope.deleted):
                    result[project_id] = scan_id

        unresolved = {pid: scope for pid, scope in scopes.items() if pid not in result}
        if not unresolved:
            return await self._resolved_to_freshest(result)

        by_default_branch: dict[str, list[str]] = {}
        for project_id, scope in unresolved.items():
            if scope.default_branch and scope.default_branch not in scope.deleted:
                by_default_branch.setdefault(scope.default_branch, []).append(project_id)
        result.update(
            await self._newest_head_per_project(
                [
                    {"project_id": {"$in": project_ids}, "branch": branch, "status": {"$in": SCAN_USABLE_STATUSES}}
                    for branch, project_ids in by_default_branch.items()
                ]
            )
        )

        # A default branch this instance never scanned — CI wired to another one, or a repo whose
        # tip predates the integration — must leave the project visible rather than empty.
        or_conditions: list[dict[str, Any]] = []
        without_deleted: list[str] = []
        for project_id, scope in unresolved.items():
            if project_id in result:
                continue
            if scope.deleted:
                or_conditions.append(
                    {
                        "project_id": project_id,
                        "branch": {"$nin": scope.deleted},
                        "status": {"$in": SCAN_USABLE_STATUSES},
                    }
                )
            else:
                without_deleted.append(project_id)
        if without_deleted:
            or_conditions.append({"project_id": {"$in": without_deleted}, "status": {"$in": SCAN_USABLE_STATUSES}})
        result.update(await self._newest_head_per_project(or_conditions))
        return await self._resolved_to_freshest(result)

    async def _resolved_to_freshest(self, tips: dict[str, str]) -> dict[str, str]:
        """The second half of the head rule: each project's tip commit swapped for the freshest
        analysis of it. A tip whose analysis vanished between the two reads drops out, which is
        what "projects resolving to no scan are omitted" already means."""
        lineage = await self.freshest_in_lineage(tips.values())
        return {
            project_id: lineage[scan_id].scan_id for project_id, scan_id in tips.items() if scan_id in lineage
        }

    async def iterate(
        self, query: dict[str, Any], projection: dict[str, int] | None = None
    ) -> AsyncGenerator[dict[str, Any], None]:
        async for doc in self.collection.find(query, projection):
            yield doc

    async def aggregate(self, pipeline: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
        with track_db_operation(_COL, "aggregate"):
            return await self.collection.aggregate(pipeline).to_list(limit)

    async def distinct(self, field: str, query: dict[str, Any] | None = None) -> list[Any]:
        return await self.collection.distinct(field, query or {})
