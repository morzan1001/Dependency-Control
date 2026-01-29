"""
Scan Repository

Centralizes all database operations for scans.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Scan


class ScanRepository:
    """Repository for scan database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.scans

    async def get_by_id(self, scan_id: str) -> Optional[Scan]:
        """Get scan by ID."""
        data = await self.collection.find_one({"_id": scan_id})
        if data:
            return Scan(**data)
        return None

    async def get_raw_by_id(
        self, scan_id: str, projection: Optional[Dict[str, int]] = None
    ) -> Optional[Dict[str, Any]]:
        """Get raw scan document by ID."""
        return await self.collection.find_one({"_id": scan_id}, projection)

    async def find_one_raw(
        self, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None
    ) -> Optional[Dict[str, Any]]:
        """Find one raw scan document matching query."""
        return await self.collection.find_one(query, projection)

    async def create(self, scan: Scan) -> Scan:
        """Create a new scan."""
        await self.collection.insert_one(scan.model_dump(by_alias=True))
        return scan

    async def update(self, scan_id: str, update_data: Dict[str, Any]) -> Optional[Scan]:
        """Update scan by ID."""
        await self.collection.update_one({"_id": scan_id}, {"$set": update_data})
        return await self.get_by_id(scan_id)

    async def update_raw(self, scan_id: str, update_ops: Dict[str, Any]) -> None:
        """Update scan with raw MongoDB operations."""
        await self.collection.update_one({"_id": scan_id}, update_ops)

    async def delete(self, scan_id: str) -> bool:
        """Delete scan by ID."""
        result = await self.collection.delete_one({"_id": scan_id})
        return result.deleted_count > 0

    async def delete_many(self, query: Dict[str, Any]) -> int:
        """Delete multiple scans matching query."""
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
        """Find scans for a project with pagination."""
        cursor = (
            self.collection.find({"project_id": project_id}, projection)
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(limit)

    async def find_one(
        self, query: Dict[str, Any], sort: Optional[List[tuple]] = None
    ) -> Optional[Dict[str, Any]]:
        """Find one scan matching query."""
        if sort:
            return await self.collection.find_one(query, sort=sort)
        return await self.collection.find_one(query)

    async def find_many(
        self,
        query: Dict[str, Any],
        projection: Optional[Dict[str, int]] = None,
        sort: Optional[List[tuple]] = None,
        skip: int = 0,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Find multiple scans matching query."""
        cursor = self.collection.find(query, projection)
        if sort:
            cursor = cursor.sort(sort)
        if skip:
            cursor = cursor.skip(skip)
        if limit:
            cursor = cursor.limit(limit)
        return await cursor.to_list(limit)

    # Alias for consistency with other repositories
    async def find_many_raw(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort: Optional[List[tuple]] = None,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Dict[str, Any]]:
        """Alias for find_many() - returns raw dicts."""
        return await self.find_many(query, projection, sort, skip, limit)

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count scans matching query."""
        return await self.collection.count_documents(query or {})

    async def get_latest_for_project(
        self, project_id: str, status: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get latest scan for a project."""
        query: Dict[str, Any] = {"project_id": project_id}
        if status:
            query["status"] = status
        return await self.collection.find_one(query, sort=[("created_at", -1)])

    async def get_pending_scans(self) -> List[Dict[str, Any]]:
        """Get all pending scans."""
        cursor = self.collection.find({"status": "pending"})
        return await cursor.to_list(None)

    async def iterate(
        self, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None
    ):
        """Iterate over scans matching query (async generator)."""
        async for doc in self.collection.find(query, projection):
            yield doc

    async def claim_pending_scan(
        self, scan_id: str, worker_id: str
    ) -> Optional[Dict[str, Any]]:
        """Atomically claim a pending scan for processing."""
        return await self.collection.find_one_and_update(
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

    async def aggregate(
        self, pipeline: List[Dict[str, Any]], limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Run aggregation pipeline."""
        return await self.collection.aggregate(pipeline).to_list(limit)

    async def distinct(
        self, field: str, query: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """Get distinct values for a field."""
        return await self.collection.distinct(field, query or {})
