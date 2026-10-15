from datetime import datetime, timezone

from pydantic import Field

from app.models.types import MongoDocument


class ArchiveMetadata(MongoDocument):
    project_id: str
    scan_id: str
    s3_key: str
    s3_bucket: str
    archived_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Snapshot of the scan, so archives list without S3 access.
    branch: str | None = None
    commit_hash: str | None = None
    scan_created_at: datetime | None = None
    scan_completed_at: datetime | None = None
    scan_status: str | None = None

    compressed_size_bytes: int | None = None

    # Content summary, so archives list without a download.
    findings_count: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    dependencies_count: int = 0
    sbom_filenames: list[str] = Field(default_factory=list)
