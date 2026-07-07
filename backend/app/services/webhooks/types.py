"""TypedDict definitions for webhook payloads."""

from typing import Any, Dict, List, Optional, TypedDict


class ScanPayload(TypedDict):
    id: str
    url: Optional[str]


class ProjectPayload(TypedDict):
    id: str
    name: str


class BaseWebhookPayload(TypedDict):
    event: str
    timestamp: str
    scan: ScanPayload
    project: ProjectPayload


class FindingsStats(TypedDict):
    total: int
    stats: Dict[str, Any]


class ScanCompletedPayload(BaseWebhookPayload):
    findings: FindingsStats


class VulnerabilityInfo(TypedDict):
    critical: int
    high: int
    kev: int
    high_epss: int
    top: List[Dict[str, Any]]


class VulnerabilityFoundPayload(BaseWebhookPayload):
    vulnerabilities: VulnerabilityInfo


class AnalysisFailedPayload(BaseWebhookPayload):
    error: str


class TestWebhookPayload(TypedDict):
    event: str
    timestamp: str
    test: bool
    message: str
    scan: ScanPayload
    project: ProjectPayload
