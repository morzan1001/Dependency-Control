"""
Pydantic schemas for database projections.

These schemas define minimal models for performance-critical queries
that only need specific fields.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.stats import Stats
from app.models.types import PyObjectId


class ProjectIdOnly(BaseModel):
    """Project with only ID field."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")


class ProjectWithScanId(BaseModel):
    """Project with ID, name, and latest scan ID."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    name: str
    latest_scan_id: Optional[str] = None

    class Config:
        populate_by_name = True


class ScanWithStats(BaseModel):
    """Scan with ID and stats."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    stats: Optional[Stats] = None

    class Config:
        populate_by_name = True


class ScanMinimal(BaseModel):
    """Scan with minimal fields for lookups."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    pipeline_id: Optional[int] = None
    is_rescan: Optional[bool] = None
    original_scan_id: Optional[str] = None
    status: Optional[str] = None
    reachability_pending: Optional[bool] = None
    project_id: Optional[str] = None

    class Config:
        populate_by_name = True


class CallgraphMinimal(BaseModel):
    """Callgraph with minimal fields."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    module_usage: Optional[dict] = None
    import_map: Optional[dict] = None
    language: Optional[str] = None

    class Config:
        populate_by_name = True
