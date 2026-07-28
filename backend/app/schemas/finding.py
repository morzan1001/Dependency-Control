from typing import Any, TypedDict

from app.models.finding import Severity


class VulnerabilityEnrichmentData(TypedDict, total=False):
    """EPSS and CISA KEV enrichment data for a vulnerability."""

    cve: str
    epss_score: float | None  # 0.0 - 1.0
    epss_percentile: float | None  # 0.0 - 100.0
    epss_date: str | None
    is_kev: bool
    kev_date_added: str | None
    kev_due_date: str | None
    kev_required_action: str | None
    kev_ransomware_use: bool
    exploit_maturity: str  # unknown, low, medium, high, active, weaponized
    risk_score: float | None  # 0-100


class VulnerabilityEntry(TypedDict, total=False):
    id: str
    severity: Severity
    description: str
    description_source: str
    fixed_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    references: list[str]
    aliases: list[str]
    scanners: list[str]
    source: str | None
    details: dict[str, Any]
    enrichment: VulnerabilityEnrichmentData


class SecretDetails(TypedDict):
    detector: str
    decoder: str | None
    verified: bool | None
    redacted: str | None
    commit: str | None
    commit_timestamp: str | None
    line: int | None
    in_current_tree: bool | None
    risk_score: float
    adjusted_risk_score: float


class VulnerabilityAggregatedDetails(TypedDict, total=False):
    vulnerabilities: list[VulnerabilityEntry]
    fixed_version: str | None
    max_epss_score: float | None
    has_kev: bool
    has_active_exploit: bool
    max_risk_score: float | None
    kev_count: int


class QualityEntry(TypedDict, total=False):
    """A single quality issue entry (from scorecard, maintainer_risk, etc.)."""

    id: str
    type: str  # "scorecard", "maintainer_risk", etc.
    severity: str
    description: str
    scanners: list[str]
    source: str | None
    details: dict[str, Any]


class QualityAggregatedDetails(TypedDict, total=False):
    """Aggregated quality data from multiple sources."""

    quality_issues: list[QualityEntry]
    overall_score: float | None
    has_maintenance_issues: bool
    issue_count: int
    scanners: list[str]
