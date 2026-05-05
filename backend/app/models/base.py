"""Shared base models for MongoDB-backed documents."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class CreatedAtModel(BaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
