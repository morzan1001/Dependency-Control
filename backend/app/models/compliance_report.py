"""
ComplianceReport — one document per report job (pending → generating →
completed/failed). Artifact lives in GridFS; metadata persists after the
artifact expires.
"""

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import Field

from app.models.types import MongoDocument
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus


class ComplianceReport(MongoDocument):
    scope: Literal["project", "team", "global", "user"]
    scope_id: Optional[str] = None
    framework: ReportFramework
    format: ReportFormat
    status: ReportStatus
    requested_by: str
    requested_at: datetime
    completed_at: Optional[datetime] = None
    artifact_gridfs_id: Optional[str] = None
    artifact_filename: Optional[str] = None
    artifact_size_bytes: Optional[int] = None
    artifact_mime_type: Optional[str] = None
    policy_version_snapshot: Optional[int] = None
    iana_catalog_version_snapshot: Optional[int] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    expires_at: Optional[datetime] = None
    comment: Optional[str] = None
