"""Repository for scans."""

from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import track_db_operation
from app.models.project import Scan
from app.schemas.projections import ScanMinimal, ScanWithStats

_COL = "scans"


class ScanRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.scans

    async def get_by_id(self, scan_id: str) -> Optional[Scan]:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": scan_id})
        if data:
            return Scan(**data)
        return None

    async def get_minimal_by_id(self, scan_id: str) -> Optional[ScanMinimal]:
        data = await self.collection.find_one(
            {"_id": scan_id},
            {
                "_id": 1,
                "pipeline_id": 1,
                "is_rescan": 1,
                "original_scan_id": 1,
                "status": 1,
                "reachability_pending": 1,
                "project_id": 1,
            },
        )
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
        cursor = self.collection.find(query, projection)
        if sort:
            cursor = cursor.sort(sort)
        if skip:
            cursor = cursor.skip(skip)
        if limit:
            cursor = cursor.limit(limit)
        docs = await cursor.to_list(limit)
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

    async def iterate(
        self, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        async for doc in self.collection.find(query, projection):
            yield doc

    async def claim_pending_scan(self, scan_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
        """Atomically flip a scan from 'pending' → 'in_progress'."""
        result: Optional[Dict[str, Any]] = await self.collection.find_one_and_update(
            {"_id": scan_id, "status": "pending"},
            {
                "$set": {
                    "status": "in_progress",
                    "worker_id": worker_id,
                    "started_at": datetime.now(timezone.utc),
                }
            },
            return_document=True,
        )
        return result

    async def aggregate(self, pipeline: List[Dict[str, Any]], limit: Optional[int] = None) -> List[Dict[str, Any]]:
        with track_db_operation(_COL, "aggregate"):
            return await self.collection.aggregate(pipeline).to_list(limit)

    async def distinct(self, field: str, query: Optional[Dict[str, Any]] = None) -> List[Any]:
        return await self.collection.distinct(field, query or {})
