"""
TypedDict definitions for webhook payloads.

Provides type-safe dictionary structures for webhook event payloads,
ensuring consistent payload structure across all webhook events.
"""

from typing import Any, Dict, List, Optional, TypedDict


class ScanPayload(TypedDict):
    """Scan information included in webhook payloads."""

    id: str
    url: Optional[str]


class ProjectPayload(TypedDict):
    """Project information included in webhook payloads."""

    id: str
    name: str


class BaseWebhookPayload(TypedDict):
    """Base payload structure shared by all webhook events."""

    event: str
    timestamp: str
    scan: ScanPayload
    project: ProjectPayload


class FindingsStats(TypedDict):
    """Statistics about scan findings."""

    total: int
    stats: Dict[str, Any]


class ScanCompletedPayload(BaseWebhookPayload):
    """Payload for scan_completed webhook events."""

    findings: FindingsStats


class VulnerabilityInfo(TypedDict):
    """Vulnerability counts and details."""

    critical: int
    high: int
    kev: int
    high_epss: int
    top: List[Dict[str, Any]]


class VulnerabilityFoundPayload(BaseWebhookPayload):
    """Payload for vulnerability_found webhook events."""

    vulnerabilities: VulnerabilityInfo


class AnalysisFailedPayload(BaseWebhookPayload):
    """Payload for analysis_failed webhook events."""

    error: str


class TestWebhookPayload(TypedDict):
    """Payload for test webhook requests."""

    event: str
    timestamp: str
    test: bool
    message: str
    scan: ScanPayload
    project: ProjectPayload
