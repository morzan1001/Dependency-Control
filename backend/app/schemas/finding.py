from typing import Any, Dict, List, Optional, TypedDict

from app.models.finding import Severity


class VulnerabilityEnrichmentData(TypedDict, total=False):
    """EPSS and CISA KEV enrichment data for a vulnerability."""

    cve: str
    epss_score: Optional[float]  # 0.0 - 1.0
    epss_percentile: Optional[float]  # 0.0 - 100.0
    epss_date: Optional[str]
    is_kev: bool
    kev_date_added: Optional[str]
    kev_due_date: Optional[str]
    kev_required_action: Optional[str]
    kev_ransomware_use: bool
    exploit_maturity: str  # unknown, low, medium, high, active, weaponized
    risk_score: Optional[float]  # 0-100


class VulnerabilityEntry(TypedDict, total=False):
    id: str
    severity: Severity
    description: str
    description_source: str
    fixed_version: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    references: List[str]
    aliases: List[str]
    scanners: List[str]
    source: Optional[str]
    details: Dict[str, Any]
    enrichment: VulnerabilityEnrichmentData


class SecretDetails(TypedDict):
    detector: str
    decoder: Optional[str]
    verified: Optional[bool]
    redacted: Optional[str]
    commit: Optional[str]
    commit_timestamp: Optional[str]
    line: Optional[int]
    in_current_tree: Optional[bool]
    risk_score: float
    adjusted_risk_score: float


class VulnerabilityAggregatedDetails(TypedDict, total=False):
    vulnerabilities: List[VulnerabilityEntry]
    fixed_version: Optional[str]
    max_epss_score: Optional[float]
    has_kev: bool
    has_active_exploit: bool
    max_risk_score: Optional[float]
    kev_count: int


class QualityEntry(TypedDict, total=False):
    """A single quality issue entry (from scorecard, maintainer_risk, etc.)."""

    id: str
    type: str  # "scorecard", "maintainer_risk", etc.
    severity: str
    description: str
    scanners: List[str]
    source: Optional[str]
    details: Dict[str, Any]


class QualityAggregatedDetails(TypedDict, total=False):
    """Aggregated quality data from multiple sources."""

    quality_issues: List[QualityEntry]
    overall_score: Optional[float]
    has_maintenance_issues: bool
    issue_count: int
    scanners: List[str]
