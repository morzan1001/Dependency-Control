"""Pydantic models and TypedDicts for analytics API endpoints."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class CVEEnrichmentResult(BaseModel):
    """Result of CVE enrichment data processing from process_cve_enrichments()."""

    max_epss: float | None = None
    max_percentile: float | None = None
    max_risk: float | None = None
    has_kev: bool = False
    kev_count: int = 0
    kev_ransomware_use: bool = False
    kev_due_date: str | None = None
    exploit_maturity: str = "unknown"
    days_until_due: int | None = None


class SeverityBreakdown(BaseModel):
    """Breakdown of findings by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    info: int = 0
    unknown: int = 0


class DependencyUsage(BaseModel):
    """Usage statistics for a dependency across projects."""

    name: str
    type: str
    versions: list[str]
    project_count: int
    total_occurrences: int
    has_vulnerabilities: bool
    vulnerability_count: int


class DependencyTreeNode(BaseModel):
    """A dependency and the ids of its direct children; the client expands children lazily."""

    id: str
    name: str
    version: str
    purl: str
    type: str
    direct: bool
    direct_inferred: bool = False
    has_findings: bool
    findings_count: int
    findings_severity: SeverityBreakdown | None = None
    child_ids: list[str] = []
    source_type: str | None = None
    source_target: str | None = None
    layer_digest: str | None = None
    locations: list[str] = []


class DependencyGraph(BaseModel):
    """Flat unique dependency nodes + the ids to render at top level; the client nests lazily."""

    # Every node is reachable from roots (direct deps, unresolved-parent deps, one entry per
    # otherwise-disconnected component), so the graph is rendered whole without server nesting.
    nodes: list[DependencyTreeNode] = []
    roots: list[str] = []


class ImpactAnalysisResult(BaseModel):
    """Result of impact analysis for a component."""

    component: str
    version: str
    affected_projects: int
    total_findings: int
    findings_by_severity: SeverityBreakdown
    recommended_version: str | None = None
    fix_impact_score: float
    affected_project_names: list[str]
    max_epss_score: float | None = None
    epss_percentile: float | None = None
    has_kev: bool = False
    kev_count: int = 0
    kev_ransomware_use: bool = False
    kev_due_date: str | None = None  # Earliest CISA remediation deadline
    days_until_due: int | None = None  # negative when overdue
    exploit_maturity: str = "unknown"
    max_risk_score: float | None = None
    days_known: int | None = None
    has_fix: bool = False
    fix_versions: list[str] = []
    priority_reasons: list[str] = []


class VulnerabilityHotspot(BaseModel):
    """A vulnerability hotspot - component with many findings."""

    component: str
    version: str
    type: str
    finding_count: int
    severity_breakdown: SeverityBreakdown
    affected_projects: list[str]
    first_seen: str
    max_epss_score: float | None = None
    epss_percentile: float | None = None
    has_kev: bool = False
    kev_count: int = 0
    kev_ransomware_use: bool = False
    kev_due_date: str | None = None  # Earliest CISA remediation deadline
    days_until_due: int | None = None  # negative when overdue
    exploit_maturity: str = "unknown"
    max_risk_score: float | None = None
    days_known: int | None = None
    has_fix: bool = False
    fix_versions: list[str] = []
    top_cves: list[str] = []
    priority_reasons: list[str] = []


class DependencyTypeStats(BaseModel):
    """Statistics for a dependency type."""

    type: str
    count: int
    percentage: float


class AnalyticsSummary(BaseModel):
    """Summary of analytics across all accessible projects."""

    total_dependencies: int
    total_vulnerabilities: int
    unique_packages: int
    dependency_types: list[DependencyTypeStats]
    severity_distribution: SeverityBreakdown


class DependencyMetadata(BaseModel):
    """Aggregated metadata for a dependency across all projects."""

    name: str
    version: str
    type: str
    purl: str | None = None

    description: str | None = None
    author: str | None = None
    publisher: str | None = None
    homepage: str | None = None
    repository_url: str | None = None
    download_url: str | None = None
    group: str | None = None

    license: str | None = None
    license_url: str | None = None
    license_category: str | None = None
    license_risks: list[str] = []
    license_obligations: list[str] = []

    deps_dev: dict[str, Any] | None = None

    project_count: int = 0
    affected_projects: list[dict[str, Any]] = []  # [{id, name, direct}]
    total_vulnerability_count: int = 0
    total_finding_count: int = 0

    enrichment_sources: list[str] = []


class VulnerabilitySearchResult(BaseModel):
    """Result of a vulnerability/CVE search."""

    vulnerability_id: str  # e.g. CVE-2021-44228, GHSA-xxx
    aliases: list[str] = []

    severity: str
    cvss_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None

    in_kev: bool = False
    kev_ransomware: bool = False
    kev_due_date: str | None = None

    component: str
    version: str
    component_type: str | None = None
    purl: str | None = None

    project_id: str
    project_name: str
    scan_id: str | None = None

    finding_id: str
    finding_type: str
    description: str | None = None
    fixed_version: str | None = None

    waived: bool = False
    waiver_reason: str | None = None


class VulnerabilitySearchResponse(BaseModel):
    """Paginated response for vulnerability search."""

    items: list[VulnerabilitySearchResult]
    total: int
    page: int
    size: int


class DependencySearchResult(BaseModel):
    """Result of a dependency search."""

    project_id: str
    project_name: str
    package: str
    version: str
    type: str
    license: str | None = None
    license_url: str | None = None
    direct: bool = False
    purl: str | None = None
    source_type: str | None = None
    source_target: str | None = None
    layer_digest: str | None = None
    found_by: str | None = None
    locations: list[str] = []
    cpes: list[str] = []
    description: str | None = None
    author: str | None = None
    publisher: str | None = None
    group: str | None = None
    homepage: str | None = None
    repository_url: str | None = None
    download_url: str | None = None
    hashes: dict[str, Any] = {}
    properties: dict[str, Any] = {}


class DependencySearchResponse(BaseModel):
    """Paginated response for dependency search."""

    items: list[DependencySearchResult]
    total: int
    page: int
    size: int


class RecommendationResponse(BaseModel):
    """Response model for a single recommendation."""

    type: str
    priority: str
    title: str
    description: str
    impact: dict[str, Any]
    affected_components: list[str]
    action: dict[str, Any]
    effort: str


class RecommendationsResponse(BaseModel):
    """Response model for recommendations endpoint."""

    project_id: str
    project_name: str
    scan_id: str
    total_findings: int
    total_vulnerabilities: int
    recommendations: list[RecommendationResponse]
    summary: dict[str, Any]


# --- Update Frequency Analysis ---


class DependencyUpdateEvent(BaseModel):
    """A single dependency version change between two consecutive scans."""

    package_name: str
    package_type: str
    purl: str | None = None
    old_version: str
    new_version: str
    update_type: str  # "patch" | "minor" | "major" | "unknown" | "downgrade"
    scan_date: str  # ISO timestamp of the scan where the update was detected
    previous_scan_date: str
    days_between_scans: int
    was_outdated: bool  # was flagged as outdated in the previous scan


class ScanTimelineEntry(BaseModel):
    """Per-scan summary for timeline chart data."""

    scan_id: str
    date: str
    updates_count: int  # excludes downgrades
    outdated_count: int
    patch: int
    minor: int
    major: int
    unknown: int = 0
    downgrades: int = 0


class SlowPackage(BaseModel):
    """A package that remains outdated across multiple scans."""

    name: str
    type: str
    current_version: str | None = None
    latest_version: str | None = None
    scans_outdated: int  # number of scans where this package was flagged as outdated


class UpdateFrequencyMetrics(BaseModel):
    """Aggregated update frequency metrics for a single project."""

    project_id: str
    project_name: str
    # Branch the timeline covers; None only when the project has no completed scans.
    branch: str | None = None
    scan_count: int
    time_range_days: float
    first_scan_date: str
    last_scan_date: str

    # Downgrades/rollbacks are tracked separately and never counted as updates.
    total_updates: int
    updates_per_scan: float
    updates_per_month: float  # extrapolated from time_range_days

    patch_updates: int
    minor_updates: int
    major_updates: int
    unknown_updates: int
    downgrade_updates: int = 0
    granularity_ratio: dict[str, float]  # {"patch": 0.6, "minor": 0.3, "major": 0.1}

    avg_days_between_scans: float

    # Coverage — share of ever-outdated packages that were resolved.
    # None means nothing was ever outdated (N/A, distinct from 0%).
    total_outdated_detected: int
    outdated_resolved: int
    update_coverage_pct: float | None = None

    trend_direction: str  # "improving" | "stable" | "deteriorating" | "unknown"
    trend_detail: str

    # Upstream release cadence (independent of scan frequency).
    # All four are None when no release-history data is available.
    upstream_releases_last_12m_median: float | None = None
    upstream_days_between_releases_median: float | None = None
    upstream_days_since_latest_release_median: float | None = None
    adoption_latency_days_median: float | None = None  # release-to-first-scan lag

    # Dominant dep ecosystem ("pypi"/"npm"/...); "mixed" if none >=70%; None if empty.
    dominant_ecosystem: str | None = None

    scan_timeline: list[ScanTimelineEntry]
    slowest_packages: list[SlowPackage]
    recent_updates: list[DependencyUpdateEvent]


class ProjectUpdateSummary(BaseModel):
    """Lightweight update metrics for cross-project comparison."""

    project_id: str
    project_name: str
    team_name: str | None = None
    scan_count: int
    updates_per_month: float
    update_coverage_pct: float | None = None
    patch_ratio: float  # proportion of patch updates (0-1)
    trend_direction: str  # "improving" | "stable" | "deteriorating" | "unknown"
    total_outdated: int
    last_scan_date: str


class UpdateFrequencyComparison(BaseModel):
    """Cross-project comparison of update frequency metrics.

    Ranking: measured coverage first (descending), then projects where
    nothing was ever outdated (no measurable coverage). best/worst are
    drawn from measured projects only.
    """

    projects: list[ProjectUpdateSummary]
    team_avg_updates_per_month: float
    team_avg_coverage_pct: float | None = None  # None when no project has measurable coverage
    best_project: str | None = None
    worst_project: str | None = None
    skipped_projects: int = 0  # projects dropped for lacking >=2 completed scans


# Crypto analytics schemas


class HotspotEntry(BaseModel):
    """A single entry in a crypto hotspot report."""

    key: str = Field(..., description="Grouping key (e.g., 'RSA-1024')")
    grouping_dimension: str = Field(..., description="Dimension this entry groups by")
    asset_count: int = Field(..., ge=0)
    finding_count: int = Field(..., ge=0)
    severity_mix: dict[str, int] = Field(default_factory=dict)
    locations: list[str] = Field(default_factory=list)
    project_ids: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime


class HotspotResponse(BaseModel):
    """Paginated hotspot response for a given scope."""

    scope: Literal["project", "team", "global", "user"]
    scope_id: str | None = None
    grouping_dimension: str
    items: list[HotspotEntry] = Field(default_factory=list)
    total: int = Field(..., ge=0)
    generated_at: datetime
    cache_hit: bool = False


class TrendPoint(BaseModel):
    """A single data point in a trend time-series."""

    timestamp: datetime
    metric: str
    value: float


class TrendSeries(BaseModel):
    """A full trend time-series for a metric within a scope."""

    scope: str
    scope_id: str | None = None
    metric: str
    bucket: Literal["day", "week", "month"]
    points: list[TrendPoint] = Field(default_factory=list)
    range_start: datetime
    range_end: datetime
    cache_hit: bool = False
