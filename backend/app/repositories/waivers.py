"""
Waiver Repository

Centralizes all database operations for waivers.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.waiver import Waiver


class WaiverRepository:
    """Repository for waiver database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.waivers

    async def get_by_id(self, waiver_id: str) -> Optional[Waiver]:
        """Get waiver by ID."""
        data = await self.collection.find_one({"_id": waiver_id})
        if data:
            return Waiver(**data)
        return None

    async def get_raw_by_id(self, waiver_id: str) -> Optional[Dict[str, Any]]:
        """Get raw waiver document by ID."""
        return await self.collection.find_one({"_id": waiver_id})

    async def create(self, waiver: Waiver) -> Waiver:
        """Create a new waiver."""
        await self.collection.insert_one(waiver.model_dump(by_alias=True))
        return waiver

    async def update(
        self, waiver_id: str, update_data: Dict[str, Any]
    ) -> Optional[Waiver]:
        """Update waiver by ID."""
        await self.collection.update_one({"_id": waiver_id}, {"$set": update_data})
        return await self.get_by_id(waiver_id)

    async def delete(self, waiver_id: str) -> bool:
        """Delete waiver by ID."""
        result = await self.collection.delete_one({"_id": waiver_id})
        return result.deleted_count > 0

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Find waivers for a project."""
        cursor = (
            self.collection.find({"project_id": project_id}).skip(skip).limit(limit)
        )
        return await cursor.to_list(limit)

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 1000,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Dict[str, Any]]:
        """Find multiple waivers matching query."""
        cursor = (
            self.collection.find(query)
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(limit)

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count waivers matching query."""
        return await self.collection.count_documents(query or {})

    async def find_active_for_project(
        self, project_id: str, include_global: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Find all active (non-expired) waivers for a project.

        Includes both project-specific and global waivers (project_id=None).
        This is the standard method used by scan_manager and stats modules.

        Args:
            project_id: Project ID to find waivers for
            include_global: Whether to include global waivers (default: True)

        Returns:
            List of waiver documents (raw dicts for performance)
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        if include_global:
            # Include both project-specific and global waivers
            query = {
                "$and": [
                    {
                        "$or": [
                            {"project_id": project_id},
                            {"project_id": None},  # Global waivers
                        ]
                    },
                    {
                        "$or": [
                            {"expiration_date": {"$exists": False}},
                            {"expiration_date": None},
                            {"expiration_date": {"$gt": now}},
                        ]
                    },
                ]
            }
        else:
            # Only project-specific waivers
            query = {
                "$and": [
                    {"project_id": project_id},
                    {
                        "$or": [
                            {"expiration_date": {"$exists": False}},
                            {"expiration_date": None},
                            {"expiration_date": {"$gt": now}},
                        ]
                    },
                ]
            }

        cursor = self.collection.find(query)
        return await cursor.to_list(length=10000)

    async def find_by_finding(
        self, project_id: str, finding_id: str
    ) -> Optional[Waiver]:
        """Find waiver for a specific finding."""
        data = await self.collection.find_one(
            {
                "project_id": project_id,
                "finding_id": finding_id,
            }
        )
        if data:
            return Waiver(**data)
        return None

    async def find_by_package(self, project_id: str, package_name: str) -> List[Waiver]:
        """Find waivers for a specific package."""
        cursor = self.collection.find(
            {
                "project_id": project_id,
                "package_name": package_name,
            }
        )
        docs = await cursor.to_list(None)
        return [Waiver(**doc) for doc in docs]
