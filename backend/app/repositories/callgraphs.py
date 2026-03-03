"""
Callgraph Repository

Centralizes all database operations for callgraphs.
"""

from typing import List, Optional

from app.models.callgraph import Callgraph
from app.repositories.base import BaseRepository
from app.schemas.projections import CallgraphMinimal

_MINIMAL_PROJECTION = {"_id": 1, "module_usage": 1, "import_map": 1, "language": 1}


class CallgraphRepository(BaseRepository[Callgraph]):
    """Repository for callgraph database operations."""

    collection_name = "callgraphs"
    model_class = Callgraph

    # --- Single callgraph ---

    async def get_by_project(self, project_id: str) -> Optional[Callgraph]:
        """Get callgraph by project ID."""
        return await self.find_one({"project_id": project_id})

    async def get_minimal_by_project(self, project_id: str) -> Optional[CallgraphMinimal]:
        """Get callgraph with minimal fields by project ID (performance optimized)."""
        data = await self.collection.find_one({"project_id": project_id}, _MINIMAL_PROJECTION)
        return CallgraphMinimal(**data) if data else None

    async def get_by_scan(self, project_id: str, scan_id: str) -> Optional[Callgraph]:
        """Get callgraph by project and scan ID."""
        return await self.find_one({"project_id": project_id, "scan_id": scan_id})

    async def get_minimal_by_scan(self, project_id: str, scan_id: str) -> Optional[CallgraphMinimal]:
        """Get callgraph with minimal fields by project and scan ID (performance optimized)."""
        data = await self.collection.find_one({"project_id": project_id, "scan_id": scan_id}, _MINIMAL_PROJECTION)
        return CallgraphMinimal(**data) if data else None

    async def get_by_pipeline(self, project_id: str, pipeline_id: int) -> Optional[Callgraph]:
        """Get callgraph by project and pipeline ID."""
        return await self.find_one({"project_id": project_id, "pipeline_id": pipeline_id})

    async def get_minimal_by_pipeline(self, project_id: str, pipeline_id: int) -> Optional[CallgraphMinimal]:
        """Get callgraph with minimal fields by project and pipeline ID (performance optimized)."""
        data = await self.collection.find_one(
            {"project_id": project_id, "pipeline_id": pipeline_id}, _MINIMAL_PROJECTION
        )
        return CallgraphMinimal(**data) if data else None

    # --- All callgraphs (multi-language) ---

    async def find_all_minimal_by_scan(self, project_id: str, scan_id: str) -> List[CallgraphMinimal]:
        """Get all callgraphs (all languages) with minimal fields for a scan."""
        cursor = self.collection.find({"project_id": project_id, "scan_id": scan_id}, _MINIMAL_PROJECTION)
        return [CallgraphMinimal(**doc) async for doc in cursor]

    async def find_all_minimal_by_pipeline(self, project_id: str, pipeline_id: int) -> List[CallgraphMinimal]:
        """Get all callgraphs (all languages) with minimal fields for a pipeline."""
        cursor = self.collection.find({"project_id": project_id, "pipeline_id": pipeline_id}, _MINIMAL_PROJECTION)
        return [CallgraphMinimal(**doc) async for doc in cursor]

    async def find_all_minimal_by_project(self, project_id: str) -> List[CallgraphMinimal]:
        """Get all callgraphs (all languages) with minimal fields for a project."""
        cursor = self.collection.find({"project_id": project_id}, _MINIMAL_PROJECTION)
        return [CallgraphMinimal(**doc) async for doc in cursor]

    # --- Delete ---

    async def delete_by_project(self, project_id: str) -> int:
        """Delete all callgraphs by project ID."""
        return await self.delete_many({"project_id": project_id})

    async def delete_by_scan(self, project_id: str, scan_id: str) -> int:
        """Delete all callgraphs by project and scan ID."""
        return await self.delete_many({"project_id": project_id, "scan_id": scan_id})
