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
