"""Shared base models for MongoDB-backed documents."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class CreatedAtModel(BaseModel):
    """Provides a UTC-stamped `created_at` field."""

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TimestampedModel(CreatedAtModel):
    """Provides UTC-stamped `created_at` and `updated_at` fields."""

    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
