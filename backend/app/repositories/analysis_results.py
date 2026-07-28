"""Repository for analysis results."""

from app.models.project import AnalysisResult
from app.repositories.base import BaseRepository


class AnalysisResultRepository(BaseRepository[AnalysisResult]):
    collection_name = "analysis_results"
    model_class = AnalysisResult

    async def find_by_scan(
        self,
        scan_id: str,
        limit: int = 1000,
    ) -> list[AnalysisResult]:
        return await self.find_many({"scan_id": scan_id}, limit=limit)

    async def find_by_scan_ids(
        self,
        scan_ids: list[str],
        limit: int = 1000,
    ) -> list[AnalysisResult]:
        return await self.find_many({"scan_id": {"$in": scan_ids}}, limit=limit)

    async def delete_by_scan(self, scan_id: str) -> int:
        return await self.delete_many({"scan_id": scan_id})
