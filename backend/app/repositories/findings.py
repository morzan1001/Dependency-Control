"""
Finding Repository

Centralizes all database operations for findings.
"""

from typing import Any, Dict, List, Optional

from pymongo import UpdateOne

from app.models.finding_record import FindingRecord
from app.repositories.base import BaseRepository


class FindingRepository(BaseRepository[FindingRecord]):
    """Repository for finding database operations."""

    collection_name = "findings"
    model_class = FindingRecord

    async def apply_vulnerability_waiver(
        self,
        scan_id: str,
        vulnerability_id: str,
        waived: bool,
        waiver_reason: Optional[str] = None,
    ) -> int:
        """
        Apply waiver to specific vulnerability within findings.
        Uses MongoDB array_filters to update nested vulnerability objects.
        """
        update_data = {"details.vulnerabilities.$[vuln].waived": waived}
        if waiver_reason:
            update_data["details.vulnerabilities.$[vuln].waiver_reason"] = waiver_reason

        result = await self.collection.update_many(
            {
                "scan_id": scan_id,
                "type": "vulnerability",
                "details.vulnerabilities.id": vulnerability_id,
            },
            {"$set": update_data},
            array_filters=[{"vuln.id": vulnerability_id}],
        )
        return result.modified_count

    async def apply_finding_waiver(
        self,
        scan_id: str,
        query: dict,
        waived: bool,
        waiver_reason: Optional[str] = None,
    ) -> int:
        """Apply waiver to findings matching query (for non-vulnerability or finding-level waivers)."""
        full_query = {"scan_id": scan_id, **query}
        update_data = {"waived": waived}
        if waiver_reason:
            update_data["waiver_reason"] = waiver_reason

        result = await self.collection.update_many(full_query, {"$set": update_data})
        return result.modified_count

    async def find_by_scan(
        self,
        scan_id: str,
        skip: int = 0,
        limit: int = 1000,
        query_filter: Optional[Dict[str, Any]] = None,
    ) -> List[FindingRecord]:
        """Find findings for a scan."""
        query: Dict[str, Any] = {"scan_id": scan_id}
        if query_filter:
            query.update(query_filter)
        return await self.find_many(query, skip=skip, limit=limit)

    async def find_by_scan_raw(
        self,
        scan_id: str,
        skip: int = 0,
        limit: int = 1000,
        query_filter: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Find raw findings for a scan."""
        query: Dict[str, Any] = {"scan_id": scan_id}
        if query_filter:
            query.update(query_filter)
        return await self.find_many_raw(query, skip=skip, limit=limit)

    async def delete_by_scan(self, scan_id: str) -> int:
        """Delete all findings for a scan."""
        return await self.delete_many({"scan_id": scan_id})

    async def count_by_scan(self, scan_id: str) -> int:
        """Count findings for a scan."""
        return await self.count({"scan_id": scan_id})

    async def bulk_upsert(self, operations: List[UpdateOne]) -> int:
        """Bulk upsert findings."""
        if not operations:
            return 0
        result = await self.collection.bulk_write(operations)
        return result.upserted_count + result.modified_count

    async def get_severity_counts(self, scan_id: str) -> Dict[str, int]:
        """Get finding counts by severity for a scan."""
        pipeline = [
            {"$match": {"scan_id": scan_id}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results if r["_id"]}

    async def get_type_counts(self, scan_id: str) -> Dict[str, int]:
        """Get finding counts by type for a scan."""
        pipeline = [
            {"$match": {"scan_id": scan_id}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results if r["_id"]}

    async def get_severity_distribution(
        self,
        scan_ids: List[str],
        finding_type: str = "vulnerability",
    ) -> Dict[str, int]:
        """
        Get severity distribution across multiple scans.

        Args:
            scan_ids: List of scan IDs to aggregate
            finding_type: Type of findings to count (default: vulnerability)

        Returns:
            Dict mapping severity to count: {"CRITICAL": 5, "HIGH": 10, ...}
        """
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}, "type": finding_type}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results if r["_id"]}

    async def get_vuln_counts_by_components(
        self,
        project_ids: List[str],
        component_names: List[str],
    ) -> Dict[str, int]:
        """
        Get vulnerability counts per component across projects.

        Args:
            project_ids: List of project IDs to search
            component_names: List of component names to count

        Returns:
            Dict mapping component name to vulnerability count
        """
        pipeline: List[Dict[str, Any]] = [
            {
                "$match": {
                    "project_id": {"$in": project_ids},
                    "component": {"$in": component_names},
                    "type": "vulnerability",
                }
            },
            {"$group": {"_id": "$component", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results}
