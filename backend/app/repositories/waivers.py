"""Repository for waivers."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import track_db_operation
from app.models.waiver import Waiver

_COL = "waivers"


def _non_expired_filter(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Return a MongoDB $or clause matching waivers whose expiration_date is absent, null, or in the future."""
    ts = now or datetime.now(timezone.utc)
    return {
        "$or": [{"expiration_date": {"$exists": False}}, {"expiration_date": None}, {"expiration_date": {"$gt": ts}}]
    }


class WaiverRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.waivers

    async def get_by_id(self, waiver_id: str) -> Optional[Waiver]:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": waiver_id})
        if data:
            return Waiver(**data)
        return None

    async def get_raw_by_id(self, waiver_id: str) -> Optional[Dict[str, Any]]:
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"_id": waiver_id})

    async def create(self, waiver: Waiver) -> Waiver:
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(waiver.model_dump(by_alias=True))
        return waiver

    async def update(self, waiver_id: str, update_data: Dict[str, Any]) -> Optional[Waiver]:
        with track_db_operation(_COL, "update_one"):
            await self.collection.update_one({"_id": waiver_id}, {"$set": update_data})
        return await self.get_by_id(waiver_id)

    async def delete(self, waiver_id: str) -> bool:
        with track_db_operation(_COL, "delete_one"):
            result = await self.collection.delete_one({"_id": waiver_id})
        return result.deleted_count > 0

    async def delete_many(self, query: Dict[str, Any]) -> int:
        with track_db_operation(_COL, "delete_many"):
            result = await self.collection.delete_many(query)
        return result.deleted_count

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Returns raw dicts (not Waiver models) to avoid model overhead in bulk listings."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find({"project_id": project_id}).skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 1000,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Dict[str, Any]]:
        """Returns raw dicts (not Waiver models) to avoid model overhead in bulk listings."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(query or {})

    async def find_active_for_project(self, project_id: str, include_global: bool = True) -> List[Waiver]:
        """Active (non-expired) waivers for a project; include_global also matches global waivers (project_id=None)."""
        now = datetime.now(timezone.utc)

        project_filter = (
            {"$or": [{"project_id": project_id}, {"project_id": None}]}
            if include_global
            else {"project_id": project_id}
        )
        query: Dict[str, Any] = {"$and": [project_filter, _non_expired_filter(now=now)]}

        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query)
            docs = await cursor.to_list(None)
        return [Waiver(**doc) for doc in docs]

    async def find_by_finding(self, project_id: str, finding_id: str) -> Optional[Waiver]:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one(
                {
                    "project_id": project_id,
                    "finding_id": finding_id,
                }
            )
        if data:
            return Waiver(**data)
        return None
