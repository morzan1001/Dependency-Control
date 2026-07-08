"""Repository for callgraphs."""

from typing import List

from app.models.callgraph import Callgraph
from app.repositories.base import BaseRepository
from app.schemas.projections import CallgraphMinimal

_MINIMAL_PROJECTION = {"_id": 1, "module_usage": 1, "import_map": 1, "language": 1}


class CallgraphRepository(BaseRepository[Callgraph]):
    collection_name = "callgraphs"
    model_class = Callgraph

    async def find_all_minimal_by_scan(self, project_id: str, scan_id: str) -> List[CallgraphMinimal]:
        cursor = self.collection.find({"project_id": project_id, "scan_id": scan_id}, _MINIMAL_PROJECTION)
        return [CallgraphMinimal(**doc) async for doc in cursor]

    async def find_all_minimal_by_pipeline(self, project_id: str, pipeline_id: int) -> List[CallgraphMinimal]:
        cursor = self.collection.find({"project_id": project_id, "pipeline_id": pipeline_id}, _MINIMAL_PROJECTION)
        return [CallgraphMinimal(**doc) async for doc in cursor]

    async def delete_by_project(self, project_id: str) -> int:
        return await self.delete_many({"project_id": project_id})

    async def delete_by_scan(self, project_id: str, scan_id: str) -> int:
        return await self.delete_many({"project_id": project_id, "scan_id": scan_id})
