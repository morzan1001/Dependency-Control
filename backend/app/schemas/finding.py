from typing import Any, TypedDict

from app.models.finding import Severity


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
    ecosystem_specific: dict[str, Any]


class VulnerabilityAggregatedDetails(TypedDict, total=False):
    vulnerabilities: list[VulnerabilityEntry]
    fixed_version: str | None


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
