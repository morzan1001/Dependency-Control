"""TypedDict definitions for webhook payloads."""

from typing import Any, TypedDict


class ScanPayload(TypedDict):
    id: str
    url: str | None


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
    stats: dict[str, Any]


class ScanCompletedPayload(BaseWebhookPayload):
    findings: FindingsStats
    scan_status: str
    failed_analyzers: list[str]


class VulnerabilityInfo(TypedDict):
    critical: int
    high: int
    kev: int
    high_epss: int
    top: list[dict[str, Any]]


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
