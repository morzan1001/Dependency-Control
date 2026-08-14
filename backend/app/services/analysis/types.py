"""Type definitions for the analysis module."""

from datetime import datetime
from typing import Any, TypedDict

from motor.motor_asyncio import AsyncIOMotorDatabase

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
    due_date: str | None
    ransomware: bool


class HighRiskCVE(TypedDict):
    """Details about a high-risk CVE."""

    cve: str
    component: str
    version: str
    risk_score: float
    epss_score: float | None
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
    avg_epss_score: float | None
    max_epss_score: float | None
    # Mean/max of the per-finding threat score (EPSS, KEV and exploit maturity) over this
    # scan's vulnerability findings — NOT the project-level exposure score of the same name
    # on the dashboard, which averages projects' saturating severity-weighted stats.risk_score.
    avg_risk_score: float | None
    max_risk_score: float | None
    kev_details: list[KEVDetail]
    high_risk_cves: list[HighRiskCVE]
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
    generated_at: str | None


class VulnerabilityInfo(TypedDict, total=False):
    """Basic info about a vulnerability for reachability analysis."""

    cve: str
    component: str
    version: str
    severity: str
    reachability_level: str
    reachable_functions: list[str]
    # True only when confidence_score cleared REACHABILITY_HIGH_CONFIDENCE_THRESHOLD.
    is_high_confidence: bool


class ReachabilitySummary(TypedDict):
    """Summary of reachability analysis data."""

    total_vulnerabilities: int
    analyzed: int
    reachability_levels: ReachabilityLevelCounts
    callgraph_info: list[CallgraphInfo]
    languages: list[str]
    reachable_vulnerabilities: list[VulnerabilityInfo]
    unreachable_vulnerabilities: list[VulnerabilityInfo]
    timestamp: str


class FindingDict(TypedDict, total=False):
    """A finding document as stored in the database."""

    _id: str
    scan_id: str
    project_id: str | None
    finding_id: str
    id: str
    type: str
    severity: str
    component: str
    version: str | None
    description: str
    scanners: list[str]
    details: dict[str, Any]
    found_in: list[str]
    aliases: list[str]
    related_findings: list[str]
    waived: bool
    waiver_reason: str | None
    reachable: bool | None
    reachability_level: str | None
    reachable_functions: list[str]


class WaiverDict(TypedDict, total=False):
    """A waiver document as stored in the database."""

    _id: str
    project_id: str | None
    finding_id: str | None
    package_name: str | None
    package_version: str | None
    finding_type: str | None
    vulnerability_id: str | None
    reason: str
    status: str
    expiration_date: datetime | None
    created_by: str
    created_at: datetime


class ScanDict(TypedDict, total=False):
    """A scan document as stored in the database."""

    _id: str
    project_id: str
    branch: str
    commit_hash: str | None
    pipeline_id: int | None
    pipeline_iid: int | None
    status: str
    is_rescan: bool
    original_scan_id: str | None
    latest_rescan_id: str | None
    last_result_at: datetime | None
    received_results: list[str]


class LatestRunSummary(TypedDict):
    """Summary of the latest analysis run."""

    scan_id: str
    status: str
    findings_count: int
    stats: dict[str, Any]
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
    smtp_host: str | None
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    smtp_encryption: str
    emails_from_email: str

    # Integrations
    github_token: str | None
    open_source_malware_api_key: str | None
    slack_bot_token: str | None
    slack_client_id: str | None
    slack_client_secret: str | None
    slack_refresh_token: str | None
    slack_token_expires_at: float | None
    mattermost_bot_token: str | None
    mattermost_url: str | None

    # OIDC / SSO
    oidc_enabled: bool
    oidc_provider_name: str
    oidc_client_id: str | None
    oidc_client_secret: str | None
    oidc_issuer: str | None
    oidc_authorization_endpoint: str | None
    oidc_token_endpoint: str | None
    oidc_userinfo_endpoint: str | None
    oidc_scopes: str

    # GitLab Integration
    gitlab_integration_enabled: bool
    gitlab_url: str
    gitlab_access_token: str | None
    gitlab_auto_create_projects: bool
    gitlab_sync_teams: bool
    gitlab_oidc_audience: str | None

    # Periodic Scanning Defaults
    rescan_mode: str
    global_rescan_enabled: bool
    global_rescan_interval: int

    # Retention
    retention_mode: str
    global_retention_days: int
