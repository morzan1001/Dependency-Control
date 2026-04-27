"""Repository for finding database operations."""

from typing import Any, Dict, List, Optional

from pymongo import UpdateOne

from app.models.finding_record import FindingRecord
from app.repositories.base import BaseRepository


class FindingRepository(BaseRepository[FindingRecord]):
    collection_name = "findings"
    model_class = FindingRecord

    async def ensure_indexes(self) -> None:
        await self.collection.create_index([("project_id", 1), ("scan_created_at", 1)])
        await self.collection.create_index([("type", 1), ("scan_created_at", 1)])

    async def apply_vulnerability_waiver(
        self,
        scan_id: str,
        vulnerability_id: str,
        waived: bool,
        waiver_reason: Optional[str] = None,
    ) -> int:
        """Apply waiver to a specific nested vulnerability via array_filters."""
        update_data: Dict[str, Any] = {"details.vulnerabilities.$[vuln].waived": waived}
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
        """Apply waiver to findings matching `query` (finding-level, not nested-vulnerability)."""
        full_query = {"scan_id": scan_id, **query}
        update_data: Dict[str, Any] = {"waived": waived}
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
        query: Dict[str, Any] = {"scan_id": scan_id}
        if query_filter:
            query.update(query_filter)
        return await self.find_many(query, skip=skip, limit=limit)

    async def delete_by_scan(self, scan_id: str) -> int:
        return await self.delete_many({"scan_id": scan_id})

    async def count_by_scan(self, scan_id: str) -> int:
        return await self.count({"scan_id": scan_id})

    async def bulk_upsert(self, operations: List[UpdateOne]) -> int:
        if not operations:
            return 0
        result = await self.collection.bulk_write(operations)
        return result.upserted_count + result.modified_count

    async def get_severity_distribution(
        self,
        scan_ids: List[str],
        finding_type: str = "vulnerability",
    ) -> Dict[str, int]:
        """Returns {severity: count} of non-waived findings aggregated across `scan_ids`."""
        pipeline: List[Dict[str, Any]] = [
            {
                "$match": {
                    "scan_id": {"$in": scan_ids},
                    "type": finding_type,
                    "waived": {"$ne": True},
                }
            },
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results if r["_id"]}

    async def get_vuln_counts_by_components(
        self,
        project_ids: List[str],
        component_names: List[str],
    ) -> Dict[str, int]:
        """Returns {component_name: non_waived_vulnerability_count} across `project_ids`."""
        pipeline: List[Dict[str, Any]] = [
            {
                "$match": {
                    "project_id": {"$in": project_ids},
                    "component": {"$in": component_names},
                    "type": "vulnerability",
                    "waived": {"$ne": True},
                }
            },
            {"$group": {"_id": "$component", "count": {"$sum": 1}}},
        ]
        results = await self.aggregate(pipeline)
        return {r["_id"]: r["count"] for r in results}
