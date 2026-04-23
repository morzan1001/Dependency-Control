"""Response schemas for the PQC migration plan generator."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class MigrationItemStatus(str, Enum):
    MIGRATE_NOW = "migrate_now"         # priority >= 80
    MIGRATE_SOON = "migrate_soon"       # 50..79
    PLAN_MIGRATION = "plan_migration"   # 25..49
    MONITOR = "monitor"                 # 0..24


class MigrationItem(BaseModel):
    asset_bom_ref: str
    asset_name: str
    asset_variant: Optional[str] = None
    asset_key_size_bits: Optional[int] = None
    project_ids: List[str] = Field(default_factory=list)
    asset_count: int = Field(..., ge=1)

    source_family: str
    source_primitive: str
    use_case: str
    recommended_pqc: str
    recommended_standard: str
    notes: str

    priority_score: int = Field(..., ge=0, le=100)
    status: MigrationItemStatus
    recommended_deadline: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)


class MigrationPlanSummary(BaseModel):
    total_items: int
    status_counts: Dict[str, int] = Field(default_factory=dict)
    earliest_deadline: Optional[str] = None


class MigrationPlanResponse(BaseModel):
    scope: str
    scope_id: Optional[str] = None
    generated_at: datetime
    items: List[MigrationItem] = Field(default_factory=list)
    summary: MigrationPlanSummary
    mappings_version: int
