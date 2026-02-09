"""
Type definitions for the analysis module.

Provides type-safe definitions for data structures used in analysis.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

from motor.motor_asyncio import AsyncIOMotorDatabase

# Type alias for the database connection
Database = AsyncIOMotorDatabase


class EPSSScoreCounts(TypedDict):
    """Counts of findings by EPSS score range."""

    high: int  # > 0.1 (10%)
    medium: int  # 0.01 - 0.1 (1-10%)
    low: int  # < 0.01 (< 1%)


class ExploitMaturityCounts(TypedDict):
    """Counts of findings by exploit maturity level."""

    weaponized: int
    active: int
    high: int
    medium: int
    low: int
    unknown: int


class KEVDetail(TypedDict):
    """Details about a vulnerability in the CISA KEV catalog."""

    cve: str
    component: str
    due_date: Optional[str]
    ransomware: bool


class HighRiskCVE(TypedDict):
    """Details about a high-risk CVE."""

    cve: str
    component: str
    version: str
    risk_score: float
    epss_score: Optional[float]
    in_kev: bool
    exploit_maturity: str


class EPSSKEVSummary(TypedDict):
    """Summary of EPSS/KEV enrichment data."""

    total_vulnerabilities: int
    epss_enriched: int
    kev_matches: int
    kev_ransomware: int
    epss_scores: EPSSScoreCounts
    exploit_maturity: ExploitMaturityCounts
    avg_epss_score: Optional[float]
    max_epss_score: Optional[float]
    avg_risk_score: Optional[float]
    max_risk_score: Optional[float]
    kev_details: List[KEVDetail]
    high_risk_cves: List[HighRiskCVE]
    timestamp: str


class ReachabilityLevelCounts(TypedDict):
    """Counts of findings by reachability level."""

    confirmed: int  # Symbol-level match
    likely: int  # Import-level match
    unknown: int  # Could not determine
    unreachable: int  # Confirmed not used


class CallgraphInfo(TypedDict):
    """Information about the callgraph used for analysis."""

    language: str
    total_modules: int
    total_imports: int
    generated_at: Optional[str]


class VulnerabilityInfo(TypedDict):
    """Basic info about a vulnerability for reachability analysis."""

    cve: str
    component: str
    version: str
    severity: str
    reachability_level: str
    reachable_functions: List[str]


class ReachabilitySummary(TypedDict):
    """Summary of reachability analysis data."""

    total_vulnerabilities: int
    analyzed: int
    reachability_levels: ReachabilityLevelCounts
    callgraph_info: CallgraphInfo
    reachable_vulnerabilities: List[VulnerabilityInfo]
    unreachable_vulnerabilities: List[VulnerabilityInfo]
    timestamp: str


class FindingDict(TypedDict, total=False):
    """A finding document as stored in the database."""

    _id: str
    scan_id: str
    project_id: Optional[str]
    finding_id: str
    id: str
    type: str
    severity: str
    component: str
    version: Optional[str]
    description: str
    scanners: List[str]
    details: Dict[str, Any]
    found_in: List[str]
    aliases: List[str]
    related_findings: List[str]
    waived: bool
    waiver_reason: Optional[str]
    reachable: Optional[bool]
    reachability_level: Optional[str]
    reachable_functions: List[str]


class WaiverDict(TypedDict, total=False):
    """A waiver document as stored in the database."""

    _id: str
    project_id: Optional[str]
    finding_id: Optional[str]
    package_name: Optional[str]
    package_version: Optional[str]
    finding_type: Optional[str]
    vulnerability_id: Optional[str]
    reason: str
    status: str
    expiration_date: Optional[datetime]
    created_by: str
    created_at: datetime


class ScanDict(TypedDict, total=False):
    """A scan document as stored in the database."""

    _id: str
    project_id: str
    branch: str
    commit_hash: Optional[str]
    pipeline_id: Optional[int]
    pipeline_iid: Optional[int]
    status: str
    is_rescan: bool
    original_scan_id: Optional[str]
    latest_rescan_id: Optional[str]
    last_result_at: Optional[datetime]
    received_results: List[str]


class LatestRunSummary(TypedDict):
    """Summary of the latest analysis run."""

    scan_id: str
    status: str
    findings_count: int
    stats: Dict[str, Any]
    completed_at: datetime


class SystemSettingsDict(TypedDict, total=False):
    """System settings as stored in the database."""

    _id: str

    # General
    instance_name: str

    # Limits
    project_limit_per_user: int

    # Security
    allow_public_registration: bool
    enforce_2fa: bool
    enforce_email_verification: bool

    # Email / SMTP
    smtp_host: Optional[str]
    smtp_port: int
    smtp_user: Optional[str]
    smtp_password: Optional[str]
    smtp_encryption: str
    emails_from_email: str

    # Integrations
    github_token: Optional[str]
    open_source_malware_api_key: Optional[str]
    slack_bot_token: Optional[str]
    slack_client_id: Optional[str]
    slack_client_secret: Optional[str]
    slack_refresh_token: Optional[str]
    slack_token_expires_at: Optional[float]
    mattermost_bot_token: Optional[str]
    mattermost_url: Optional[str]

    # OIDC / SSO
    oidc_enabled: bool
    oidc_provider_name: str
    oidc_client_id: Optional[str]
    oidc_client_secret: Optional[str]
    oidc_issuer: Optional[str]
    oidc_authorization_endpoint: Optional[str]
    oidc_token_endpoint: Optional[str]
    oidc_userinfo_endpoint: Optional[str]
    oidc_scopes: str

    # GitLab Integration
    gitlab_integration_enabled: bool
    gitlab_url: str
    gitlab_access_token: Optional[str]
    gitlab_auto_create_projects: bool
    gitlab_sync_teams: bool
    gitlab_oidc_audience: Optional[str]

    # Periodic Scanning Defaults
    rescan_mode: str
    global_rescan_enabled: bool
    global_rescan_interval: int

    # Retention
    retention_mode: str
    global_retention_days: int
