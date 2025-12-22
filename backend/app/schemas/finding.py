from typing import Any, Dict, List, Optional, TypedDict

from app.models.finding import Severity


class VulnerabilityEnrichmentData(TypedDict, total=False):
    """EPSS and CISA KEV enrichment data for a vulnerability."""
    cve: str
    epss_score: Optional[float]  # 0.0 - 1.0, probability of exploitation in 30 days
    epss_percentile: Optional[float]  # 0.0 - 100.0, percentile rank
    epss_date: Optional[str]
    is_kev: bool  # Is in CISA Known Exploited Vulnerabilities catalog
    kev_date_added: Optional[str]
    kev_due_date: Optional[str]
    kev_required_action: Optional[str]
    kev_ransomware_use: bool
    exploit_maturity: str  # unknown, low, medium, high, active, weaponized
    risk_score: Optional[float]  # Combined risk score 0-100


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
    # Enrichment data (EPSS, KEV)
    enrichment: VulnerabilityEnrichmentData


class SecretDetails(TypedDict):
    detector: str
    decoder: Optional[str]
    verified: Optional[bool]
    redacted: Optional[str]


class VulnerabilityAggregatedDetails(TypedDict, total=False):
    vulnerabilities: List[VulnerabilityEntry]
    fixed_version: Optional[str]
    # Aggregated enrichment summary
    max_epss_score: Optional[float]  # Highest EPSS score among vulnerabilities
    has_kev: bool  # Any vuln is in CISA KEV
    has_active_exploit: bool  # Any vuln has active/weaponized exploit
    max_risk_score: Optional[float]  # Highest combined risk score
    kev_count: int  # Number of vulns in KEV


class QualityEntry(TypedDict, total=False):
    """A single quality issue entry (from scorecard, maintainer_risk, etc.)."""
    id: str
    type: str  # "scorecard", "maintainer_risk", etc.
    severity: str
    description: str
    scanners: List[str]
    source: Optional[str]
    details: Dict[str, Any]  # Scanner-specific details


class QualityAggregatedDetails(TypedDict, total=False):
    """Aggregated quality data from multiple sources."""
    quality_issues: List[QualityEntry]
    # Computed summary fields
    overall_score: Optional[float]  # Best available score (from scorecard)
    has_maintenance_issues: bool
    issue_count: int
    scanners: List[str]
