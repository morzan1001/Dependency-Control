"""Repository for scans."""

from collections.abc import AsyncGenerator
from typing import Any, NamedTuple

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ReadPreference

from app.core.constants import SCAN_USABLE_STATUSES
from app.core.metrics import track_db_operation
from app.models.project import Scan
from app.schemas.projections import ScanMinimal, ScanWithStats

_COL = "scans"
_RESCAN_RANK = "_rescan_rank"

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
        limit: int = 1000,
    ) -> list[ScanWithStats]:
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

    async def _newest_head_per_project(self, or_conditions: list[dict[str, Any]]) -> dict[str, str]:
        if not or_conditions:
            return {}
        with track_db_operation(_COL, "aggregate"):
            cursor = self.collection.aggregate(_head_pipeline(or_conditions))
            return {doc["_id"]: doc["scan_id"] async for doc in cursor}

    async def get_latest_active_scan_ids(self, projects: list[Any]) -> dict[str, str]:
        """Maps project_id -> the scan that represents its head: the newest usable build on the
        default branch, or on any branch the VCS still has when no default is known; projects
        resolving to no scan are omitted.
        """
        scopes: dict[str, _HeadScope] = {}
        for project in projects:
            project_id, scope = _head_scope(project)
            if project_id:
                scopes[project_id] = scope
        return await self._head_scan_ids(scopes)

    async def _head_scan_ids(self, scopes: dict[str, _HeadScope]) -> dict[str, str]:
        """The one head resolver. ``latest_scan_id`` is head cached by ingest, so it is trusted
        only while it still names a readable scan on the head branch."""
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
            return result

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
        return result

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
