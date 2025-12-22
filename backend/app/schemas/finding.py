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
