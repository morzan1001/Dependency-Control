from datetime import datetime, timezone

from pydantic import BaseModel, Field


class CreatedAtModel(BaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VcsInstanceModel(BaseModel):
    """Subclasses redeclare these fields with their metadata."""

    access_token: str | None = None
    is_active: bool = True
