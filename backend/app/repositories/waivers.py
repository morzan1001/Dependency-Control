"""Repository for waivers."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import track_db_operation
from app.models.waiver import Waiver

_COL = "waivers"


def _non_expired_filter(field: str = "expiration_date", now: Optional[datetime] = None) -> Dict[str, Any]:
    """Return a MongoDB $or clause matching documents where `field` is absent, null, or in the future."""
    ts = now or datetime.now(timezone.utc)
    return {"$or": [{field: {"$exists": False}}, {field: None}, {field: {"$gt": ts}}]}


class WaiverRepository:
    """Repository for waiver database operations."""

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
        """Get raw waiver document by ID."""
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
        """Find waivers for a project.

        Returns raw dicts (not Waiver models) for performance in bulk operations.
        When listing many waivers, avoiding model instantiation reduces overhead.

        Args:
            project_id: The project ID to filter waivers by.
            skip: Number of documents to skip (for pagination).
            limit: Maximum number of documents to return.

        Returns:
            List[Dict[str, Any]]: Raw MongoDB documents as dictionaries.
        """
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
        """Find multiple waivers matching query.

        Returns raw dicts (not Waiver models) for performance in bulk operations.
        This method is used for paginated listings and search results where
        constructing full Waiver model instances would add unnecessary overhead.

        Args:
            query: MongoDB query filter.
            skip: Number of documents to skip (for pagination).
            limit: Maximum number of documents to return.
            sort_by: Field name to sort by.
            sort_order: Sort direction (1 for ascending, -1 for descending).

        Returns:
            List[Dict[str, Any]]: Raw MongoDB documents as dictionaries.
        """
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(query or {})

    async def find_active_for_project(self, project_id: str, include_global: bool = True) -> List[Waiver]:
        """
        Find all active (non-expired) waivers for a project.

        Includes both project-specific and global waivers (project_id=None).
        This is the standard method used by scan_manager and stats modules.

        Args:
            project_id: Project ID to find waivers for
            include_global: Whether to include global waivers (default: True)

        Returns:
            List of validated Waiver model instances.
        """
        now = datetime.now(timezone.utc)

        project_filter = (
            {"$or": [{"project_id": project_id}, {"project_id": None}]}
            if include_global
            else {"project_id": project_id}
        )
        query: Dict[str, Any] = {"$and": [project_filter, _non_expired_filter(now=now)]}

        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query)
            docs = await cursor.to_list(length=10000)
        return [Waiver(**doc) for doc in docs]

    async def find_by_finding(self, project_id: str, finding_id: str) -> Optional[Waiver]:
        """Find waiver for a specific finding.

        Returns a Waiver model instance (not a raw dict) because this is a
        single-item lookup where the caller typically needs the full validated
        model for business logic (e.g., checking expiration, applying waiver).

        Args:
            project_id: The project ID to scope the search.
            finding_id: The finding ID to match.

        Returns:
            Optional[Waiver]: The Waiver model instance, or None if not found.
        """
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
