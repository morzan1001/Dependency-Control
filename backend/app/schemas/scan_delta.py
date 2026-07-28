"""Response envelopes for the unified scan-delta API (findings, components, crypto)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

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
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)


class FindingDeltaItem(BaseModel):
    """A single added/removed finding between two scans."""

    model_config = ConfigDict(extra="forbid")

    change: Literal["added", "removed"]
    finding_id: str
    finding_type: str
    severity: str
    title: str
    component: str | None = None
    cve_id: str | None = None
    file_path: str | None = None
    first_seen: datetime | None = None


class ComponentDeltaItem(BaseModel):
    """A single component change between two scans."""

    model_config = ConfigDict(extra="forbid")

    change: Literal["added", "removed", "version_changed", "license_changed"]
    name: str
    purl: str | None = None
    version: str | None = None
    from_version: str | None = None
    to_version: str | None = None
    license: str | None = None
    from_license: str | None = None
    to_license: str | None = None


class CryptoDeltaItem(BaseModel):
    """A single crypto asset change between two scans."""

    model_config = ConfigDict(extra="forbid")

    change: Literal["added", "removed"]
    name: str
    variant: str | None = None
    primitive: str | None = None
    locations: list[str] = Field(default_factory=list)
    asset_count: int = 1


DeltaItem = FindingDeltaItem | ComponentDeltaItem | CryptoDeltaItem


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
    items: list[DeltaItem] = Field(default_factory=list)
