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


class ScanDeltaTotals(BaseModel):
    """Aggregate counts for a scan-delta response."""

    model_config = ConfigDict(extra="forbid")

    added: int = 0
    removed: int = 0
    unchanged: int = 0
    # Components and findings; crypto never pairs a changed item.
    changed: int = 0
    # Findings-only breakdowns.
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)


class FindingDeltaItem(BaseModel):
    """A single finding between two scans; 'changed' is a vulnerability record whose version or advisories moved."""

    model_config = ConfigDict(extra="forbid")

    change: Literal["added", "removed", "changed"]
    finding_id: str
    finding_type: str
    severity: str
    title: str
    component: str | None = None
    cve_id: str | None = None
    file_path: str | None = None
    # The project's earliest detection of this finding, across all of its scans.
    first_seen: datetime | None = None
    from_version: str | None = None
    to_version: str | None = None
    added_cves: list[str] = Field(default_factory=list)
    dropped_cves: list[str] = Field(default_factory=list)


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


class ScanDeltaReachability(BaseModel):
    """Reachability coverage of one side of a delta. A build without a callgraph is coverable-but-unanalysed
    while the other side can be enriched, and their risk scores are then not comparable."""

    model_config = ConfigDict(extra="forbid")

    coverable_count: int = 0
    analyzed_count: int = 0


class ScanDeltaSide(BaseModel):
    """Which build one side of a delta actually is. A symbolic side resolves server-side, so
    without the branch and commit a caller cannot tell which artefact the totals describe."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    branch: str | None = None
    commit_hash: str | None = None
    created_at: datetime | None = None


class ScanDeltaResponse(BaseModel):
    """Unified response envelope for the scan-delta endpoint."""

    model_config = ConfigDict(extra="forbid")

    from_scan_id: str
    to_scan_id: str
    from_side: ScanDeltaSide | None = None
    to_side: ScanDeltaSide | None = None
    project_id: str
    category: DeltaCategory
    totals: ScanDeltaTotals
    page: int = 1
    page_size: int = 50
    total_pages: int = 1
    items: list[DeltaItem] = Field(default_factory=list)
    # None means the scan reports no reachability at all, which is distinct from zero coverage.
    # Coverage is the whole scan's, not the filtered item set's: it describes the enrichment a side
    # was scored with, so it counts every vulnerability in the scan whatever the delta asked for.
    from_reachability: ScanDeltaReachability | None = None
    to_reachability: ScanDeltaReachability | None = None
    # Wholly or partly waived findings per side, filtered by finding_type only; severity and `change` scope items.
    from_waived_excluded: int = 0
    to_waived_excluded: int = 0
    # Items a waiver-free comparison would not produce; equal waived counts can still hide different findings.
    waiver_only_changes: int = 0
