from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class ArchiveListItem(BaseModel):
    """Single archive entry in listing response."""

    id: str
    scan_id: str
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    scan_created_at: Optional[datetime] = None
    archived_at: datetime
    compressed_size_bytes: Optional[int] = None
    findings_count: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    dependencies_count: int = 0
    sbom_filenames: List[str] = Field(default_factory=list)


class AdminArchiveListItem(ArchiveListItem):
    """Archive entry with project info for admin overview."""

    project_id: str
    project_name: Optional[str] = None


class ArchiveListResponse(BaseModel):
    """Paginated list of archives for a project."""

    items: List[ArchiveListItem]
    total: int
    page: int
    size: int
    pages: int


class AdminArchiveListResponse(BaseModel):
    """Paginated list of archives across all projects (admin)."""

    items: List[AdminArchiveListItem]
    total: int
    page: int
    size: int
    pages: int


class ArchiveRestoreResponse(BaseModel):
    """Response after restoring an archive."""

    scan_id: str
    project_id: str
    message: str = "Archive restored successfully"
    collections_restored: List[str] = Field(default_factory=list)


class ScanPinResponse(BaseModel):
    """Response after pinning/unpinning a scan."""

    scan_id: str
    pinned: bool
