"""
Archive Metadata Repository

Centralizes all database operations for archive tracking records.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.archive import ArchiveMetadata
from app.repositories.base import BaseRepository


class ArchiveMetadataRepository(BaseRepository[ArchiveMetadata]):
    """Repository for archive metadata database operations."""

    collection_name = "archive_metadata"
    model_class = ArchiveMetadata

    def _build_filter_query(
        self,
        project_id: Optional[str] = None,
        branch: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Build a MongoDB filter query from optional parameters."""
        query: Dict[str, Any] = {}
        if project_id:
            query["project_id"] = project_id
        if branch:
            query["branch"] = branch
        if date_from or date_to:
            date_filter: Dict[str, Any] = {}
            if date_from:
                date_filter["$gte"] = date_from
            if date_to:
                date_filter["$lte"] = date_to
            query["scan_created_at"] = date_filter
        return query

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 50,
        branch: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> List[ArchiveMetadata]:
        """Find archives for a project, sorted by archived_at descending."""
        query = self._build_filter_query(
            project_id=project_id,
            branch=branch,
            date_from=date_from,
            date_to=date_to,
        )
        return await self.find_many(
            query=query,
            skip=skip,
            limit=limit,
            sort_by="archived_at",
            sort_order=-1,
        )

    async def count_by_project(
        self,
        project_id: str,
        branch: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> int:
        """Count archives for a project."""
        query = self._build_filter_query(
            project_id=project_id,
            branch=branch,
            date_from=date_from,
            date_to=date_to,
        )
        return await self.count(query)

    async def find_by_scan_id(self, scan_id: str) -> Optional[ArchiveMetadata]:
        """Find archive metadata by scan ID."""
        return await self.find_one({"scan_id": scan_id})

    async def delete_by_scan_id(self, scan_id: str) -> bool:
        """Delete archive metadata by scan ID."""
        result = await self.collection.delete_one({"scan_id": scan_id})
        return result.deleted_count > 0

    async def get_distinct_branches(self, project_id: str) -> List[str]:
        """Get all unique branch names for a project's archives."""
        branches: List[str] = await self.collection.distinct(
            "branch", {"project_id": project_id, "branch": {"$ne": None}}
        )
        return sorted(branches)

    async def find_all(
        self,
        skip: int = 0,
        limit: int = 50,
        branch: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        project_id: Optional[str] = None,
    ) -> List[ArchiveMetadata]:
        """Find archives across all projects (admin), sorted by archived_at descending."""
        query = self._build_filter_query(
            project_id=project_id,
            branch=branch,
            date_from=date_from,
            date_to=date_to,
        )
        return await self.find_many(
            query=query,
            skip=skip,
            limit=limit,
            sort_by="archived_at",
            sort_order=-1,
        )

    async def count_all(
        self,
        branch: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        project_id: Optional[str] = None,
    ) -> int:
        """Count archives across all projects (admin)."""
        query = self._build_filter_query(
            project_id=project_id,
            branch=branch,
            date_from=date_from,
            date_to=date_to,
        )
        return await self.count(query)
