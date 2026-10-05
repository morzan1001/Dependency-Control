"""
Pydantic schemas for database projections.

These schemas define minimal models for performance-critical queries
that only need specific fields.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import DEFAULT_ACTIVE_ANALYZERS
from app.models.stats import Stats
from app.models.types import PyObjectId


class ProjectWithScanId(BaseModel):
    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    name: str = ""
    latest_scan_id: str | None = None
    deleted_branches: list[str] = Field(default_factory=list)
    default_branch: str | None = None
    active_analyzers: list[str] = Field(default_factory=lambda: list(DEFAULT_ACTIVE_ANALYZERS))

    model_config = ConfigDict(populate_by_name=True)


class ScanWithStats(BaseModel):
    """Scan with ID and stats."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    stats: Stats | None = None

    model_config = ConfigDict(populate_by_name=True)


class ScanMinimal(BaseModel):
    """Scan with minimal fields for lookups."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    pipeline_id: int | None = None
    is_rescan: bool | None = None
    original_scan_id: str | None = None
    status: str | None = None
    reachability_pending: bool | None = None
    project_id: str | None = None

    model_config = ConfigDict(populate_by_name=True)


class CallgraphMinimal(BaseModel):
    """Callgraph fields needed for reachability and stats."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    module_usage: dict | None = None
    analyzed_modules: list[str] = Field(default_factory=list)
    language: str | None = None
    total_imports: int = 0
    created_at: datetime | None = None

    model_config = ConfigDict(populate_by_name=True)
