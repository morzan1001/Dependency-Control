from typing import Any, Dict, List, Optional, TypedDict

from app.models.finding import Severity


class VulnerabilityEntry(TypedDict):
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


class SecretDetails(TypedDict):
    detector: str
    decoder: Optional[str]
    verified: Optional[bool]
    redacted: Optional[str]


class VulnerabilityAggregatedDetails(TypedDict):
    vulnerabilities: List[VulnerabilityEntry]
    fixed_version: Optional[str]


class ScorecardEntry(TypedDict, total=False):
    """Scorecard data from deps_dev scanner."""
    overall_score: float
    scorecard_date: Optional[str]
    repository: Optional[str]
    project_url: Optional[str]
    failed_checks: List[Dict[str, Any]]
    critical_issues: List[str]
    checks_summary: Dict[str, int]
    recommendation: Optional[str]


class MaintainerRiskEntry(TypedDict, total=False):
    """Maintainer risk data from maintainer_risk scanner."""
    risks: List[Dict[str, Any]]
    maintainer_info: Dict[str, Any]
    risk_count: int


class QualityAggregatedDetails(TypedDict, total=False):
    """Aggregated quality data from multiple sources (scorecard + maintainer_risk)."""
    scorecard: Optional[ScorecardEntry]
    maintainer_risk: Optional[MaintainerRiskEntry]
    # Computed summary fields
    overall_score: Optional[float]
    has_maintenance_issues: bool
    maintenance_issues: List[str]
    scanners: List[str]
