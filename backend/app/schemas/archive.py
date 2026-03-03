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


class ArchiveListResponse(BaseModel):
    """Paginated list of archives for a project."""

    items: List[ArchiveListItem]
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
