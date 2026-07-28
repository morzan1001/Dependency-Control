"""One document per compliance-report job; artifact lives in GridFS, metadata persists after it expires."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.models.types import MongoDocument
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus


class ComplianceReport(MongoDocument):
    scope: Literal["project", "team", "global", "user"]
    scope_id: str | None = None
    framework: ReportFramework
    format: ReportFormat
    status: ReportStatus
    requested_by: str
    requested_at: datetime
    completed_at: datetime | None = None
    artifact_gridfs_id: str | None = None
    artifact_filename: str | None = None
    artifact_size_bytes: int | None = None
    artifact_mime_type: str | None = None
    policy_version_snapshot: int | None = None
    iana_catalog_version_snapshot: int | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    expires_at: datetime | None = None
    comment: str | None = None
