"""Repository for scans."""

from typing import Any, AsyncGenerator, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ReadPreference

from app.core.metrics import track_db_operation
from app.models.project import Scan
from app.schemas.projections import ScanMinimal, ScanWithStats

_COL = "scans"

_MINIMAL_PROJECTION = {
    "_id": 1,
    "pipeline_id": 1,
    "is_rescan": 1,
    "original_scan_id": 1,
    "status": 1,
    "reachability_pending": 1,
    "project_id": 1,
}


def _project_id_and_deleted(project: Any) -> tuple[Optional[str], List[str]]:
    """Extract ``(project_id, deleted_branches)`` from a Project model or raw dict."""
    if isinstance(project, dict):
        pid = project.get("_id") or project.get("id")
        deleted = project.get("deleted_branches") or []
    else:
        pid = getattr(project, "id", None) or getattr(project, "_id", None)
        deleted = getattr(project, "deleted_branches", None) or []
    return pid, list(deleted)


class ScanRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.scans

    def _primary(self) -> AsyncIOMotorCollection:
        return self.collection.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]

    async def get_by_id(self, scan_id: str) -> Optional[Scan]:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": scan_id})
        return Scan(**data) if data else None

    async def get_by_id_strong(self, scan_id: str) -> Optional[Scan]:
        with track_db_operation(_COL, "find_one"):
            data = await self._primary().find_one({"_id": scan_id})
        return Scan(**data) if data else None

    async def get_minimal_by_id(self, scan_id: str) -> Optional[ScanMinimal]:
        data = await self.collection.find_one({"_id": scan_id}, _MINIMAL_PROJECTION)
        return ScanMinimal(**data) if data else None

    async def get_minimal_by_id_strong(self, scan_id: str) -> Optional[ScanMinimal]:
        data = await self._primary().find_one({"_id": scan_id}, _MINIMAL_PROJECTION)
        return ScanMinimal(**data) if data else None

    async def create(self, scan: Scan) -> Scan:
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(scan.model_dump(by_alias=True))
        return scan

    async def upsert(self, query: Dict[str, Any], update: Dict[str, Any]) -> None:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one(query, update, upsert=True)

    async def update(self, scan_id: str, update_data: Dict[str, Any]) -> Optional[Scan]:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one({"_id": scan_id}, {"$set": update_data})
        return await self.get_by_id(scan_id)

    async def update_raw(self, scan_id: str, update_ops: Dict[str, Any]) -> None:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one({"_id": scan_id}, update_ops)

    async def delete(self, scan_id: str) -> bool:
        with track_db_operation(_COL, "delete_one"):
            result = await self.collection.delete_one({"_id": scan_id})
        return result.deleted_count > 0

    async def delete_many(self, query: Dict[str, Any]) -> int:
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
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        cursor = (
            self.collection.find({"project_id": project_id}, projection)
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(limit)

    async def find_one(self, query: Dict[str, Any], sort: Optional[List[tuple]] = None) -> Optional[Dict[str, Any]]:
        if sort:
            return await self.collection.find_one(query, sort=sort)
        return await self.collection.find_one(query)

    async def find_many(
        self,
        query: Dict[str, Any],
        sort: Optional[List[tuple]] = None,
        skip: int = 0,
        limit: Optional[int] = None,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Scan]:
        # limit=0 means unbounded in pymongo; floor to 1. None stays unbounded via to_list(None).
        safe_limit: Optional[int] = max(limit, 1) if limit is not None else None
        cursor = self.collection.find(query, projection)
        if sort:
            cursor = cursor.sort(sort)
        if skip:
            cursor = cursor.skip(skip)
        if safe_limit is not None:
            cursor = cursor.limit(safe_limit)
        docs = await cursor.to_list(safe_limit)
        return [Scan(**doc) for doc in docs]

    async def find_many_with_stats(
        self,
        query: Dict[str, Any],
        limit: int = 1000,
    ) -> List[ScanWithStats]:
        cursor = self.collection.find(query, {"_id": 1, "stats": 1}).limit(limit)
        docs = await cursor.to_list(limit)
        return [ScanWithStats(**doc) for doc in docs]

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(query or {})

    async def get_latest_for_project(self, project_id: str, status: Optional[str] = None) -> Optional[Scan]:
        query: Dict[str, Any] = {"project_id": project_id}
        if status:
            query["status"] = status
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one(query, sort=[("created_at", -1)])
        return Scan(**data) if data else None

    async def get_latest_active_scan(
        self, project: Any, deleted_branches: Optional[List[str]] = None
    ) -> Optional[Scan]:
        """Most recent completed scan for project on a non-deleted branch. project may be a model or raw dict; deleted_branches overrides the project's value (housekeeping passes the freshly-computed set before it is persisted)."""
        project_id, project_deleted = _project_id_and_deleted(project)
        deleted = deleted_branches if deleted_branches is not None else project_deleted
        query: Dict[str, Any] = {"project_id": project_id, "status": "completed"}
        if deleted:
            query["branch"] = {"$nin": deleted}
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one(query, sort=[("created_at", -1)])
        return Scan(**data) if data else None

    async def get_latest_active_scan_ids(self, projects: List[Any]) -> Dict[str, str]:
        """Maps project_id -> latest active scan_id: stored latest_scan_id when no deleted branches, else the most recent completed scan on a non-deleted branch; projects resolving to no scan are omitted. Each project may be a model or dict exposing id, deleted_branches, latest_scan_id."""
        result: Dict[str, str] = {}
        needing: List[tuple] = []
        for p in projects:
            pid, deleted = _project_id_and_deleted(p)
            latest_scan_id = p.get("latest_scan_id") if isinstance(p, dict) else getattr(p, "latest_scan_id", None)
            if not latest_scan_id:
                continue
            if deleted:
                needing.append((pid, deleted))
            else:
                result[pid] = latest_scan_id

        if not needing:
            return result

        or_conditions = [
            {"project_id": pid, "branch": {"$nin": deleted}, "status": "completed"} for pid, deleted in needing
        ]
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"$or": or_conditions}},
            {"$sort": {"created_at": -1}},
            {"$group": {"_id": "$project_id", "scan_id": {"$first": "$_id"}}},
        ]
        with track_db_operation(_COL, "aggregate"):
            cursor = self.collection.aggregate(pipeline)
            async for doc in cursor:
                result[doc["_id"]] = doc["scan_id"]
        return result

    async def iterate(
        self, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        async for doc in self.collection.find(query, projection):
            yield doc

    async def aggregate(self, pipeline: List[Dict[str, Any]], limit: Optional[int] = None) -> List[Dict[str, Any]]:
        with track_db_operation(_COL, "aggregate"):
            return await self.collection.aggregate(pipeline).to_list(limit)

    async def distinct(self, field: str, query: Optional[Dict[str, Any]] = None) -> List[Any]:
        return await self.collection.distinct(field, query or {})
