"""
Archive Metadata Repository

Centralizes all database operations for archive tracking records.
"""

from typing import List, Optional

from app.models.archive import ArchiveMetadata
from app.repositories.base import BaseRepository


class ArchiveMetadataRepository(BaseRepository[ArchiveMetadata]):
    """Repository for archive metadata database operations."""

    collection_name = "archive_metadata"
    model_class = ArchiveMetadata

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 50,
    ) -> List[ArchiveMetadata]:
        """Find archives for a project, sorted by archived_at descending."""
        return await self.find_many(
            query={"project_id": project_id},
            skip=skip,
            limit=limit,
            sort_by="archived_at",
            sort_order=-1,
        )

    async def count_by_project(self, project_id: str) -> int:
        """Count archives for a project."""
        return await self.count({"project_id": project_id})

    async def find_by_scan_id(self, scan_id: str) -> Optional[ArchiveMetadata]:
        """Find archive metadata by scan ID."""
        return await self.find_one({"scan_id": scan_id})

    async def delete_by_scan_id(self, scan_id: str) -> bool:
        """Delete archive metadata by scan ID."""
        result = await self.collection.delete_one({"scan_id": scan_id})
        return result.deleted_count > 0
