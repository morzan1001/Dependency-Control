"""
Callgraph Repository

Centralizes all database operations for callgraphs.
"""

from typing import Any, Dict, Optional

from app.models.callgraph import Callgraph
from app.repositories.base import BaseRepository


class CallgraphRepository(BaseRepository[Callgraph]):
    """Repository for callgraph database operations."""

    collection_name = "callgraphs"
    model_class = Callgraph

    async def get_by_project(self, project_id: str) -> Optional[Callgraph]:
        """Get callgraph by project ID."""
        return await self.find_one({"project_id": project_id})

    async def get_by_project_raw(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get raw callgraph by project ID."""
        return await self.find_one_raw({"project_id": project_id})

    async def get_by_scan(self, project_id: str, scan_id: str) -> Optional[Callgraph]:
        """Get callgraph by project and scan ID."""
        return await self.find_one({"project_id": project_id, "scan_id": scan_id})

    async def get_by_scan_raw(
        self, project_id: str, scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get raw callgraph by project and scan ID."""
        return await self.find_one_raw({"project_id": project_id, "scan_id": scan_id})

    async def get_by_pipeline(
        self, project_id: str, pipeline_id: int
    ) -> Optional[Callgraph]:
        """Get callgraph by project and pipeline ID."""
        return await self.find_one(
            {"project_id": project_id, "pipeline_id": pipeline_id}
        )

    async def delete_by_project(self, project_id: str) -> int:
        """Delete callgraph by project ID."""
        return await self.delete_many({"project_id": project_id})

    async def delete_by_scan(self, project_id: str, scan_id: str) -> int:
        """Delete callgraph by project and scan ID."""
        return await self.delete_many({"project_id": project_id, "scan_id": scan_id})
