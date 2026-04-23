"""
ComplianceReport — one document per report job (pending → generating →
completed/failed). Artifact lives in GridFS; metadata persists after the
artifact expires.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus


class ComplianceReport(BaseModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
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

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)
