"""Shared base models for MongoDB-backed documents."""

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class CreatedAtModel(BaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VcsInstanceModel(BaseModel):
    """Common shape of GitLab/GitHub instance models; subclasses redeclare fields with metadata."""

    access_token: Optional[str] = None
