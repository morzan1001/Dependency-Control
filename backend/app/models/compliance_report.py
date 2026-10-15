from datetime import datetime
from typing import Any

from pydantic import Field

from app.core.constants import ScopeName
from app.models.types import MongoDocument
from app.schemas.compliance import EvaluationCoverage, ReportFormat, ReportFramework, ReportStatus


class ComplianceReport(MongoDocument):
    scope: ScopeName
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
    # Without it, a reader of summary cannot tell a full evaluation from a windowed one.
    coverage: EvaluationCoverage | None = None
    error_message: str | None = None
    expires_at: datetime | None = None
    comment: str | None = None
