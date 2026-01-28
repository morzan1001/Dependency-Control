"""
Analysis Result Repository

Centralizes all database operations for analysis results.
"""

from typing import Any, Dict, List

from app.models.project import AnalysisResult
from app.repositories.base import BaseRepository


class AnalysisResultRepository(BaseRepository[AnalysisResult]):
    """Repository for analysis result database operations."""

    collection_name = "analysis_results"
    model_class = AnalysisResult

    # ===================
    # Scan-specific operations
    # ===================

    async def find_by_scan(
        self,
        scan_id: str,
        limit: int = 1000,
    ) -> List[AnalysisResult]:
        """Find analysis results for a scan."""
        return await self.find_many({"scan_id": scan_id}, limit=limit)

    async def find_by_scan_raw(
        self,
        scan_id: str,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Find raw analysis results for a scan."""
        return await self.find_many_raw({"scan_id": scan_id}, limit=limit)

    async def find_by_scan_ids(
        self,
        scan_ids: List[str],
        limit: int = 1000,
    ) -> List[AnalysisResult]:
        """Find analysis results for multiple scans."""
        return await self.find_many({"scan_id": {"$in": scan_ids}}, limit=limit)

    async def find_by_scan_ids_raw(
        self,
        scan_ids: List[str],
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Find raw analysis results for multiple scans."""
        return await self.find_many_raw({"scan_id": {"$in": scan_ids}}, limit=limit)

    async def delete_by_scan(self, scan_id: str) -> int:
        """Delete all analysis results for a scan."""
        return await self.delete_many({"scan_id": scan_id})
