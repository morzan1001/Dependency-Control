from datetime import datetime

from pydantic import BaseModel, Field


class ArchiveListItem(BaseModel):
    """Single archive entry in listing response."""

    id: str
    scan_id: str
    branch: str | None = None
    commit_hash: str | None = None
    scan_created_at: datetime | None = None
    archived_at: datetime
    compressed_size_bytes: int | None = None
    findings_count: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    dependencies_count: int = 0
    sbom_filenames: list[str] = Field(default_factory=list)


class AdminArchiveListItem(ArchiveListItem):
    """Archive entry with project info for admin overview."""

    project_id: str
    project_name: str | None = None


class ArchiveListResponse(BaseModel):
    """Paginated list of archives for a project."""

    items: list[ArchiveListItem]
    total: int
    page: int
    size: int
    pages: int


class AdminArchiveListResponse(BaseModel):
    """Paginated list of archives across all projects (admin)."""

    items: list[AdminArchiveListItem]
    total: int
    page: int
    size: int
    pages: int


class ArchiveRestoreResponse(BaseModel):
    """Response after restoring an archive."""

    scan_id: str
    project_id: str
    message: str = "Archive restored successfully"
    collections_restored: list[str] = Field(default_factory=list)


class ScanPinResponse(BaseModel):
    """Response after pinning/unpinning a scan."""

    scan_id: str
    pinned: bool
