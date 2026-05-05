"""
ComplianceReportRepository — metadata persistence for report jobs.
Artifact bytes live in GridFS; this repo stores the job-document only.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pymongo import DESCENDING

from app.core.metrics import track_db_operation
from app.models.compliance_report import ComplianceReport
from app.repositories.base import BaseRepository
from app.schemas.compliance import ReportFramework, ReportStatus


class ComplianceReportRepository(BaseRepository[ComplianceReport]):
    collection_name = "compliance_reports"
    model_class = ComplianceReport

    async def insert(self, report: ComplianceReport) -> None:
        with track_db_operation(self.collection_name, "insert_one"):
            await self.collection.insert_one(report.model_dump(by_alias=True))

    async def get(self, report_id: str) -> Optional[ComplianceReport]:
        with track_db_operation(self.collection_name, "find_one"):
            doc = await self.collection.find_one({"_id": report_id})
        return ComplianceReport.model_validate(doc) if doc else None

    async def list(
        self,
        *,
        scope: Optional[str] = None,
        scope_id: Optional[str] = None,
        framework: Optional[ReportFramework] = None,
        status: Optional[ReportStatus] = None,
        skip: int = 0,
        limit: int = 50,
        extra_filter: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceReport]:
        query: Dict[str, Any] = {}
        if scope:
            query["scope"] = scope
        if scope_id:
            query["scope_id"] = scope_id
        if framework:
            query["framework"] = framework.value if hasattr(framework, "value") else framework
        if status:
            query["status"] = status.value if hasattr(status, "value") else status
        if extra_filter:
            # Combine via $and so callers can pass an $or visibility clause
            # without colliding with the field-level filters above.
            query = {"$and": [query, extra_filter]} if query else extra_filter
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query).sort("requested_at", DESCENDING).skip(skip).limit(limit)
            docs = await cursor.to_list(length=limit)
        return [ComplianceReport.model_validate(d) for d in docs]

    async def update_status(
        self,
        report_id: str,
        *,
        status: ReportStatus,
        artifact_gridfs_id: Optional[str] = None,
        artifact_filename: Optional[str] = None,
        artifact_size_bytes: Optional[int] = None,
        artifact_mime_type: Optional[str] = None,
        summary: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        policy_version_snapshot: Optional[int] = None,
        iana_catalog_version_snapshot: Optional[int] = None,
        completed_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
    ) -> None:
        update: Dict[str, Any] = {"status": status.value if hasattr(status, "value") else status}
        for key, val in [
            ("artifact_gridfs_id", artifact_gridfs_id),
            ("artifact_filename", artifact_filename),
            ("artifact_size_bytes", artifact_size_bytes),
            ("artifact_mime_type", artifact_mime_type),
            ("summary", summary),
            ("error_message", error_message),
            ("policy_version_snapshot", policy_version_snapshot),
            ("iana_catalog_version_snapshot", iana_catalog_version_snapshot),
            ("completed_at", completed_at),
            ("expires_at", expires_at),
        ]:
            if val is not None:
                update[key] = val
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one({"_id": report_id}, {"$set": update})

    async def count_pending_for_user(self, user_id: str) -> int:
        with track_db_operation(self.collection_name, "count"):
            return await self.collection.count_documents(
                {
                    "requested_by": user_id,
                    "status": {
                        "$in": [
                            ReportStatus.PENDING.value,
                            ReportStatus.GENERATING.value,
                        ]
                    },
                }
            )

    async def delete(self, report_id: str) -> bool:
        with track_db_operation(self.collection_name, "delete_one"):
            result = await self.collection.delete_one({"_id": report_id})
        return result.deleted_count > 0
