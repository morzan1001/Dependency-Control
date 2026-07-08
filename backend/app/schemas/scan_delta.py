"""Response envelopes for the unified scan-delta API (findings, components, crypto)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class DeltaCategory(str, Enum):
    """Top-level category of delta the response describes."""

    FINDINGS = "findings"
    COMPONENTS = "components"
    CRYPTO = "crypto"


class DeltaChange(str, Enum):
    """Kinds of change an individual delta item can represent."""

    ADDED = "added"
    REMOVED = "removed"
    VERSION_CHANGED = "version_changed"
    LICENSE_CHANGED = "license_changed"


class ScanDeltaTotals(BaseModel):
    """Aggregate counts for a scan-delta response."""

    model_config = ConfigDict(extra="forbid")

    added: int = 0
    removed: int = 0
    unchanged: int = 0
    # Only set for the components category.
    changed: int = 0
    # Findings-only breakdowns.
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_type: Dict[str, int] = Field(default_factory=dict)


class FindingDeltaItem(BaseModel):
    """A single added/removed finding between two scans."""

    model_config = ConfigDict(extra="forbid")

    change: Literal["added", "removed"]
    finding_id: str
    finding_type: str
    severity: str
    title: str
    component: Optional[str] = None
    cve_id: Optional[str] = None
    file_path: Optional[str] = None
    first_seen: Optional[datetime] = None


class ComponentDeltaItem(BaseModel):
    """A single component change between two scans."""

    model_config = ConfigDict(extra="forbid")

    change: Literal["added", "removed", "version_changed", "license_changed"]
    name: str
    purl: Optional[str] = None
    version: Optional[str] = None
    from_version: Optional[str] = None
    to_version: Optional[str] = None
    license: Optional[str] = None
    from_license: Optional[str] = None
    to_license: Optional[str] = None


class CryptoDeltaItem(BaseModel):
    """A single crypto asset change between two scans."""

    model_config = ConfigDict(extra="forbid")

    change: Literal["added", "removed"]
    name: str
    variant: Optional[str] = None
    primitive: Optional[str] = None
    locations: List[str] = Field(default_factory=list)
    asset_count: int = 1


DeltaItem = Union[FindingDeltaItem, ComponentDeltaItem, CryptoDeltaItem]


class ScanDeltaResponse(BaseModel):
    """Unified response envelope for the scan-delta endpoint."""

    model_config = ConfigDict(extra="forbid")

    from_scan_id: str
    to_scan_id: str
    project_id: str
    category: DeltaCategory
    totals: ScanDeltaTotals
    page: int = 1
    page_size: int = 50
    total_pages: int = 1
    items: List[DeltaItem] = Field(default_factory=list)
