"""Type definitions for the analysis module."""

from typing import TypedDict

from motor.motor_asyncio import AsyncIOMotorDatabase

Database = AsyncIOMotorDatabase


class EPSSScoreCounts(TypedDict):
    """Counts of findings per bucket_epss bucket."""

    high: int
    medium: int
    low: int


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
    # high_risk_cves is the top-scoring sample; high_risk_total is how many cleared the threshold.
    high_risk_cves: list[HighRiskCVE]
    high_risk_total: int
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
    # Size of the coverage universe: packages the producer resolved and inspected.
    coverage_modules: int
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
    # Pre-cap counts; the vulnerability lists below are truncated samples.
    reachable_total: int
    unreachable_total: int
    reachable_vulnerabilities: list[VulnerabilityInfo]
    unreachable_vulnerabilities: list[VulnerabilityInfo]
    timestamp: str
