from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import ExploitMaturity, ScopeName
from app.schemas.pagination import Page
from app.schemas.team import TeamRef


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    info: int = 0
    unknown: int = 0

    @classmethod
    def from_counts(cls, counts: Mapping[str, int]) -> "SeverityBreakdown":
        """Keys in any case; one without its own field counts as unknown, so the fields sum to the counts."""
        buckets = dict.fromkeys(cls.model_fields, 0)
        for severity, count in counts.items():
            key = severity.lower()
            buckets[key if key in buckets else "unknown"] += count
        return cls(**buckets)


class DependencyUsage(BaseModel):
    name: str
    type: str
    group: str | None = None
    # The newest versions in use; version_count is how many distinct ones the estate holds.
    versions: list[str]
    version_count: int
    project_count: int
    total_occurrences: int
    has_vulnerabilities: bool
    vulnerability_count: int


class DependencyTreeNode(BaseModel):
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

    # Every node is reachable from roots, disconnected cycles included, so the client renders the whole graph.
    nodes: list[DependencyTreeNode] = []
    roots: list[str] = []
    # Rows the graph was built from against what the scan holds; equal unless the read saturated.
    dependencies_read: int = 0
    dependencies_total: int = 0


class ThreatIntelFields(BaseModel):
    max_epss_score: float | None = None
    epss_percentile: float | None = None
    has_kev: bool = False
    kev_count: int = 0
    kev_ransomware_use: bool = False
    kev_due_date: str | None = None  # Earliest CISA remediation deadline
    days_until_due: int | None = None  # negative when overdue
    exploit_maturity: ExploitMaturity = "unknown"
    max_risk_score: float | None = None
    days_known: int | None = None
    has_fix: bool = False
    fix_versions: list[str] = []
    fix_version_count: int = 0
    priority_reasons: list[str] = []
    # Live KEV/EPSS sources that could not be read, so their signals and the scores they raise may be missing.
    threat_intel_unavailable: list[str] = []


class ImpactAnalysisResult(ThreatIntelFields):
    component: str
    version: str
    affected_projects: int
    total_findings: int
    findings_by_severity: SeverityBreakdown
    fix_impact_score: float
    affected_project_names: list[str]


class VulnerabilityHotspot(ThreatIntelFields):
    component: str
    version: str
    type: str
    finding_count: int
    severity_breakdown: SeverityBreakdown
    affected_projects: list[str]
    affected_project_count: int = 0
    cve_count: int = 0
    first_seen: str
    top_cves: list[str] = []


class DependencyTypeStats(BaseModel):
    type: str
    count: int
    percentage: float


class AnalyticsSummary(BaseModel):
    total_dependencies: int
    total_vulnerabilities: int
    unique_packages: int
    dependency_types: list[DependencyTypeStats]
    severity_distribution: SeverityBreakdown
    resolved_projects: int
    projects_without_release: int


class AnalyticsScope(BaseModel):
    release_environments: list[str]
    resolved_projects: int
    projects_without_release: int
    # Release mode answers as of an old analysis, which reads as current without its date; null when no scan resolved.
    oldest_analysis_at: datetime | None = None


class AffectedProjectRef(BaseModel):
    id: str
    name: str
    direct: bool


class DependencyMetadata(BaseModel):
    name: str
    version: str = Field(..., description="The version the metadata describes")
    versions: list[str] = Field([], description="Every version of the package in scope, newest first")
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
    affected_projects: list[AffectedProjectRef] = []
    total_vulnerability_count: int = 0

    enrichment_sources: list[str] = []


class VulnerabilitySearchResult(BaseModel):
    vulnerability_id: str
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

    project_id: str
    project_name: str
    scan_id: str | None = None

    finding_id: str
    finding_type: str
    description: str | None = None
    fixed_version: str | None = None

    waived: bool = False
    waiver_reason: str | None = None


class VulnerabilitySearchResponse(Page[VulnerabilitySearchResult]):
    resolved_projects: int
    projects_without_release: int


class DependencySearchResult(BaseModel):
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


class DependencySearchResponse(Page[DependencySearchResult]):
    resolved_projects: int
    projects_without_release: int


class RecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str
    priority: str
    title: str
    description: str
    impact: dict[str, Any]
    affected_components: list[str]
    affected_components_total: int = Field(
        0,
        description="Components the recommendation covers, counted before the list was cut",
    )
    rank: int = Field(0, description="Position in the ranked list this recommendation came from, 0 if it was whole")
    ranked_out_of: int = Field(0, description="Candidates ranked for that list, 0 if none were ranked out")
    action: dict[str, Any]
    effort: str


class RecommendationsResponse(BaseModel):
    project_id: str
    project_name: str
    scan_id: str
    total_findings: int
    total_vulnerabilities: int
    recommendations: list[RecommendationResponse]
    summary: dict[str, Any]
    # Each read/total pair differs only when the read saturated, and the advice then covers only the rows read.
    findings_total: int = 0
    dependencies_read: int = 0
    dependencies_total: int = 0
    # Live KEV/EPSS sources that could not be read; the advice then rests on what the scan stored for them.
    threat_intel_unavailable: list[str] = []


class DependencyUpdateEvent(BaseModel):
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
    scan_id: str
    date: str
    updates_count: int  # excludes downgrades
    outdated_count: int | None  # None when the scan carried no outdated analysis
    patch: int
    minor: int
    major: int
    unknown: int = 0
    downgrades: int = 0


class SlowPackage(BaseModel):
    name: str
    type: str
    current_version: str | None = None
    latest_version: str | None = None
    scans_outdated: int


_BARS = "Timeline bars: consecutive scans of one commit count once"


class UpdateFrequencyMetrics(BaseModel):
    project_id: str
    project_name: str
    # Branch the timeline covers; None only when the project has no completed scans.
    branch: str | None = None
    scan_count: int = Field(..., description=_BARS)
    time_range_days: float
    first_scan_date: str
    last_scan_date: str

    # Downgrades/rollbacks are tracked separately and never counted as updates.
    total_updates: int
    updates_per_scan: float = Field(..., description=f"Updates per interval between bars. {_BARS}")
    # Rate over the requested calendar window; None when none was requested.
    updates_per_month: float | None

    patch_updates: int
    minor_updates: int
    major_updates: int
    unknown_updates: int
    downgrade_updates: int = 0
    granularity_ratio: dict[str, float]  # {"patch": 0.6, "minor": 0.3, "major": 0.1}

    avg_days_between_scans: float = Field(..., description=f"Average days between bars. {_BARS}")

    # Coverage of ever-outdated packages since resolved; None means nothing was ever outdated, unlike 0%.
    total_outdated_detected: int
    outdated_resolved: int
    update_coverage_pct: float | None = None

    trend_direction: str  # "improving" | "stable" | "deteriorating" | "unknown"
    trend_detail: str

    # Upstream release cadence, independent of scan frequency; all four are None without release-history data.
    upstream_releases_last_12m_median: float | None = None
    upstream_days_between_releases_median: float | None = None
    upstream_days_since_latest_release_median: float | None = None
    adoption_latency_days_median: float | None = None  # release-to-first-scan lag

    # Dominant dep ecosystem ("pypi"/"npm"/...); "mixed" if none >=70%; None if empty.
    dominant_ecosystem: str | None = None

    # Set when the branch exceeds what either read path follows, None for a whole window; scan_count counts bars.
    window_scan_cap: int | None = None
    # Set when retention keeps fewer days than the window, which the monthly rate then divides by instead.
    retention_days: int | None = None
    # Packages still outdated in the newest measured scan, counted before slowest_packages was cut.
    outdated_backlog: int = 0

    scan_timeline: list[ScanTimelineEntry]
    slowest_packages: list[SlowPackage]
    recent_updates: list[DependencyUpdateEvent]


UpdateDataStatus = Literal["ready", "partial", "pending", "insufficient_data", "error"]
"""partial: fewer scans than the window holds; pending: no delta yet; insufficient_data: under two comparable scans."""


class ProjectUpdateSummary(BaseModel):
    """Every metric field is None unless ``data_status`` is "ready" or "partial"."""

    project_id: str
    project_name: str
    teams: list[TeamRef] = Field(default_factory=list)
    data_status: UpdateDataStatus
    # Projects rarely carry a default_branch, so the row says which branch it describes.
    branch: str | None = None
    window_days: int
    scan_count: int | None = Field(None, description=_BARS)
    updates_per_month: float | None = None
    update_coverage_pct: float | None = None
    patch_ratio: float | None = None  # proportion of patch updates (0-1)
    trend_direction: str | None = None  # "improving" | "stable" | "deteriorating" | "unknown"
    total_updates: int | None = None
    total_outdated: int | None = None
    last_scan_date: str | None = None
    # Set when the branch exceeds what either read path follows; the rate stays comparable, divided by the stretch read.
    window_scan_cap: int | None = None
    # Set when retention keeps fewer days than the window, which the monthly rate then divides by instead.
    retention_days: int | None = None


class UpdateFrequencyComparison(BaseModel):
    """Ranked by coverage, then never-outdated projects; best, worst and team averages use "ready" projects only."""

    projects: list[ProjectUpdateSummary]
    team_avg_updates_per_month: float | None = None  # None when no window fixed a denominator
    team_avg_coverage_pct: float | None = None  # None when no project has measurable coverage
    best_project: str | None = None
    worst_project: str | None = None
    partial_projects: int = 0
    pending_projects: int = 0
    skipped_insufficient_data: int = 0
    skipped_error: int = 0


GroupBy = Literal["name", "primitive", "asset_type", "weakness_tag", "severity"]
Metric = Literal[
    "total_crypto_findings",
    "quantum_vulnerable_findings",
    "weak_algo_findings",
    "weak_key_findings",
    "cert_expiring_soon",
    "cert_expired",
    "unique_algorithms",
    "unique_cipher_suites",
]
Bucket = Literal["day", "week", "month"]


class HotspotEntry(BaseModel):
    key: str = Field(..., description="Grouping key (e.g., 'RSA-1024')")
    grouping_dimension: str = Field(..., description="Dimension this entry groups by")
    asset_count: int = Field(..., ge=0)
    finding_count: int = Field(..., ge=0)
    severity_mix: dict[str, int] = Field(default_factory=dict)
    locations: list[str] = Field(default_factory=list)
    locations_complete: bool = Field(
        ...,
        description="Every location this key occurs in is listed; when false a location absent "
        "from the list is unknown rather than known not to hold the key",
    )
    project_ids: list[str] = Field(default_factory=list, description="Every project holding the key")
    project_count: int = Field(..., ge=0, description="Every project holding the key")
    first_seen: datetime
    last_seen: datetime


class HotspotResponse(BaseModel):
    scope: ScopeName
    scope_id: str | None = None
    grouping_dimension: str
    items: list[HotspotEntry] = Field(default_factory=list)
    total: int = Field(..., ge=0)
    projects_total: int = Field(..., ge=0, description="Distinct projects across the items")
    heatmap_project_ids: list[str] = Field(
        default_factory=list, description="The heatmap's columns: up to 30 projects, those most items share first"
    )
    generated_at: datetime


class TrendPoint(BaseModel):
    timestamp: datetime
    metric: str
    value: float


class TrendSeries(BaseModel):
    scope: str
    scope_id: str | None = None
    metric: str
    bucket: Bucket
    points: list[TrendPoint] = Field(default_factory=list)
    range_start: datetime
    range_end: datetime
