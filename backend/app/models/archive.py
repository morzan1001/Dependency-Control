from datetime import datetime, timezone
from typing import List, Optional

from pydantic import ConfigDict, Field

from app.models.types import MongoDocument


class ArchiveMetadata(MongoDocument):
    """
    Tracks archived scan data in S3.

    Stored in the 'archive_metadata' MongoDB collection.
    Serves as the index for what is archived and where.
    """

    project_id: str
    scan_id: str
    s3_key: str  # e.g. "{project_id}/{scan_id}.json.gz"
    s3_bucket: str
    archived_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Scan metadata snapshot (for listing archives without S3 access)
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    scan_created_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    scan_status: Optional[str] = None

    # Size info
    original_size_bytes: Optional[int] = None
    compressed_size_bytes: Optional[int] = None

    # Content summary (for listing without downloading)
    findings_count: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    dependencies_count: int = 0
    sbom_filenames: List[str] = Field(default_factory=list)

    # Collections included in the archive bundle
    collections_included: List[str] = Field(
        default_factory=lambda: [
            "scans",
            "findings",
            "finding_records",
            "dependencies",
            "analysis_results",
            "callgraphs",
            "gridfs_sboms",
        ]
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)
