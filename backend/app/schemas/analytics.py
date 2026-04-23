"""
Analytics Schema Definitions

Pydantic models and TypedDicts for analytics API endpoints.
These define the response and request structures for analytics operations.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class CVEEnrichmentResult(BaseModel):
    """Result of CVE enrichment data processing from process_cve_enrichments()."""

    max_epss: Optional[float] = None
    max_percentile: Optional[float] = None
    max_risk: Optional[float] = None
    has_kev: bool = False
    kev_count: int = 0
    kev_ransomware_use: bool = False
    kev_due_date: Optional[str] = None
    exploit_maturity: str = "unknown"
    days_until_due: Optional[int] = None


class SeverityBreakdown(BaseModel):
    """Breakdown of findings by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DependencyUsage(BaseModel):
    """Usage statistics for a dependency across projects."""

    name: str
    type: str
    versions: List[str]
    project_count: int
    total_occurrences: int
    has_vulnerabilities: bool
    vulnerability_count: int


class DependencyTreeNode(BaseModel):
    """Node in a dependency tree with findings info."""

    id: str
    name: str
    version: str
    purl: str
    type: str
    direct: bool
    has_findings: bool
    findings_count: int
    findings_severity: Optional[SeverityBreakdown] = None
    children: List["DependencyTreeNode"] = []
    # Source/Origin info
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    layer_digest: Optional[str] = None
    locations: List[str] = []


class ImpactAnalysisResult(BaseModel):
    """Result of impact analysis for a component."""

    component: str
    version: str
    affected_projects: int
    total_findings: int
    findings_by_severity: SeverityBreakdown
    recommended_version: Optional[str] = None
    fix_impact_score: float
    affected_project_names: List[str]
    # EPSS/KEV enrichment
    max_epss_score: Optional[float] = None  # Highest EPSS score
    epss_percentile: Optional[float] = None  # Percentile of max EPSS
    has_kev: bool = False  # Any vuln in CISA KEV
    kev_count: int = 0  # Number of KEV vulns
    kev_ransomware_use: bool = False  # Used in ransomware campaigns
    kev_due_date: Optional[str] = None  # Earliest CISA remediation deadline
    days_until_due: Optional[int] = None  # Days until deadline (negative = overdue)
    exploit_maturity: str = "unknown"  # Highest exploit maturity level
    max_risk_score: Optional[float] = None  # Highest combined risk score
    # Days since first seen
    days_known: Optional[int] = None
    # Fix availability
    has_fix: bool = False
    fix_versions: List[str] = []
    # Priority reasoning
    priority_reasons: List[str] = []  # Human-readable reasons for priority


class VulnerabilityHotspot(BaseModel):
    """A vulnerability hotspot - component with many findings."""

    component: str
    version: str
    type: str
    finding_count: int
    severity_breakdown: SeverityBreakdown
    affected_projects: List[str]
    first_seen: str
    # EPSS/KEV enrichment
    max_epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    has_kev: bool = False
    kev_count: int = 0
    kev_ransomware_use: bool = False  # Used in ransomware campaigns
    kev_due_date: Optional[str] = None  # Earliest CISA remediation deadline
    days_until_due: Optional[int] = None  # Days until deadline (negative = overdue)
    exploit_maturity: str = "unknown"
    max_risk_score: Optional[float] = None
    # Days known
    days_known: Optional[int] = None
    # Fix availability
    has_fix: bool = False
    fix_versions: List[str] = []
    # Top CVEs for display
    top_cves: List[str] = []
    # Priority reasoning
    priority_reasons: List[str] = []


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
    dependency_types: List[DependencyTypeStats]
    severity_distribution: SeverityBreakdown


class DependencyMetadata(BaseModel):
    """Aggregated metadata for a dependency across all projects."""

    name: str
    version: str
    type: str
    purl: Optional[str] = None

    # Package metadata (dependency-specific, not project-specific)
    description: Optional[str] = None
    author: Optional[str] = None
    publisher: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    download_url: Optional[str] = None
    group: Optional[str] = None

    # License info
    license: Optional[str] = None
    license_url: Optional[str] = None
    license_category: Optional[str] = None
    license_risks: List[str] = []
    license_obligations: List[str] = []

    # deps.dev enrichment data
    deps_dev: Optional[Dict[str, Any]] = None

    # Aggregated info across projects
    project_count: int = 0
    affected_projects: List[Dict[str, Any]] = []  # [{id, name, direct}]
    total_vulnerability_count: int = 0
    total_finding_count: int = 0

    # Enrichment sources
    enrichment_sources: List[str] = []


class VulnerabilitySearchResult(BaseModel):
    """Result of a vulnerability/CVE search."""

    # Vulnerability identification
    vulnerability_id: str  # CVE-2021-44228, GHSA-xxx, etc.
    aliases: List[str] = []  # Alternative IDs (CVE <-> GHSA)

    # Severity & scoring
    severity: str
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    # KEV information
    in_kev: bool = False
    kev_ransomware: bool = False
    kev_due_date: Optional[str] = None

    # Affected component
    component: str
    version: str
    component_type: Optional[str] = None
    purl: Optional[str] = None

    # Project information
    project_id: str
    project_name: str
    scan_id: Optional[str] = None

    # Finding details
    finding_id: str
    finding_type: str
    description: Optional[str] = None
    fixed_version: Optional[str] = None

    # Status
    waived: bool = False
    waiver_reason: Optional[str] = None


class VulnerabilitySearchResponse(BaseModel):
    """Paginated response for vulnerability search."""

    items: List[VulnerabilitySearchResult]
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
    license: Optional[str] = None
    license_url: Optional[str] = None
    direct: bool = False
    purl: Optional[str] = None
    # Source/Origin info
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    layer_digest: Optional[str] = None
    found_by: Optional[str] = None
    locations: List[str] = []
    # Extended SBOM fields
    cpes: List[str] = []
    description: Optional[str] = None
    author: Optional[str] = None
    publisher: Optional[str] = None
    group: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    download_url: Optional[str] = None
    hashes: Dict[str, Any] = {}
    properties: Dict[str, Any] = {}


class DependencySearchResponse(BaseModel):
    """Paginated response for dependency search."""

    items: List[DependencySearchResult]
    total: int
    page: int
    size: int


class RecommendationResponse(BaseModel):
    """Response model for a single recommendation."""

    type: str
    priority: str
    title: str
    description: str
    impact: Dict[str, Any]
    affected_components: List[str]
    action: Dict[str, Any]
    effort: str


class RecommendationsResponse(BaseModel):
    """Response model for recommendations endpoint."""

    project_id: str
    project_name: str
    scan_id: str
    total_findings: int
    total_vulnerabilities: int
    recommendations: List[RecommendationResponse]
    summary: Dict[str, Any]


# --- Update Frequency Analysis ---


class DependencyUpdateEvent(BaseModel):
    """A single dependency version change between two consecutive scans."""

    package_name: str
    package_type: str
    purl: Optional[str] = None
    old_version: str
    new_version: str
    update_type: str  # "patch" | "minor" | "major" | "unknown"
    scan_date: str  # ISO timestamp of the scan where the update was detected
    previous_scan_date: str
    days_between_scans: int
    was_outdated: bool  # was flagged as outdated in the previous scan


class ScanTimelineEntry(BaseModel):
    """Per-scan summary for timeline chart data."""

    scan_id: str
    date: str
    updates_count: int
    outdated_count: int
    patch: int
    minor: int
    major: int


class SlowPackage(BaseModel):
    """A package that remains outdated across multiple scans."""

    name: str
    type: str
    current_version: Optional[str] = None
    latest_version: Optional[str] = None
    scans_outdated: int  # number of scans where this package was flagged as outdated


class UpdateFrequencyMetrics(BaseModel):
    """Aggregated update frequency metrics for a single project."""

    project_id: str
    project_name: str
    scan_count: int
    time_range_days: int
    first_scan_date: str
    last_scan_date: str

    # Frequency
    total_updates: int
    updates_per_scan: float
    updates_per_month: float

    # Granularity
    patch_updates: int
    minor_updates: int
    major_updates: int
    unknown_updates: int
    granularity_ratio: Dict[str, float]  # {"patch": 0.6, "minor": 0.3, "major": 0.1}

    # Scan cadence
    avg_days_between_scans: float

    # Coverage — how many outdated packages actually got updated
    total_outdated_detected: int
    outdated_resolved: int
    update_coverage_pct: float

    # Trend — comparing recent vs older scan history
    trend_direction: str  # "improving" | "stable" | "deteriorating"
    trend_detail: str

    # Chart data
    scan_timeline: List[ScanTimelineEntry]

    # Tables
    slowest_packages: List[SlowPackage]
    recent_updates: List[DependencyUpdateEvent]


class ProjectUpdateSummary(BaseModel):
    """Lightweight update metrics for cross-project comparison."""

    project_id: str
    project_name: str
    team_name: Optional[str] = None
    scan_count: int
    updates_per_month: float
    update_coverage_pct: float
    patch_ratio: float  # proportion of patch updates (0-1)
    trend_direction: str  # "improving" | "stable" | "deteriorating"
    total_outdated: int
    last_scan_date: str


class UpdateFrequencyComparison(BaseModel):
    """Cross-project comparison of update frequency metrics."""

    projects: List[ProjectUpdateSummary]
    team_avg_updates_per_month: float
    team_avg_coverage_pct: float
    best_project: Optional[str] = None
    worst_project: Optional[str] = None


# ---------------------------------------------------------------------------
# Crypto analytics schemas (Phase 2 — analytics foundations)
# ---------------------------------------------------------------------------


class HotspotEntry(BaseModel):
    """A single entry in a crypto hotspot report."""

    key: str = Field(..., description="Grouping key (e.g., 'RSA-1024')")
    grouping_dimension: str = Field(..., description="Dimension this entry groups by")
    asset_count: int = Field(..., ge=0)
    finding_count: int = Field(..., ge=0)
    severity_mix: Dict[str, int] = Field(default_factory=dict)
    locations: List[str] = Field(default_factory=list)
    project_ids: List[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime


class HotspotResponse(BaseModel):
    """Paginated hotspot response for a given scope."""

    scope: Literal["project", "team", "global", "user"]
    scope_id: Optional[str] = None
    grouping_dimension: str
    items: List[HotspotEntry] = Field(default_factory=list)
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
    scope_id: Optional[str] = None
    metric: str
    bucket: Literal["day", "week", "month"]
    points: List[TrendPoint] = Field(default_factory=list)
    range_start: datetime
    range_end: datetime
    cache_hit: bool = False


class ScanDelta(BaseModel):
    """Diff between two scans expressed as added/removed hotspot entries."""

    from_scan_id: str
    to_scan_id: str
    added: List[HotspotEntry] = Field(default_factory=list)
    removed: List[HotspotEntry] = Field(default_factory=list)
    unchanged_count: int = Field(..., ge=0)

    model_config = ConfigDict(populate_by_name=True)
