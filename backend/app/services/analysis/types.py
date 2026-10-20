from typing import TypedDict

from motor.motor_asyncio import AsyncIOMotorDatabase

Database = AsyncIOMotorDatabase


class EPSSScoreCounts(TypedDict):
    high: int
    medium: int
    low: int


class ExploitMaturityCounts(TypedDict):
    weaponized: int
    active: int
    high: int
    medium: int
    low: int
    unknown: int


class KEVDetail(TypedDict):
    cve: str
    component: str
    due_date: str | None
    ransomware: bool


class HighRiskCVE(TypedDict):
    cve: str
    component: str
    version: str
    risk_score: float
    epss_score: float | None
    in_kev: bool
    exploit_maturity: str


class EPSSKEVSummary(TypedDict):
    total_vulnerabilities: int
    epss_enriched: int
    kev_matches: int
    kev_ransomware: int
    epss_scores: EPSSScoreCounts
    exploit_maturity: ExploitMaturityCounts
    avg_epss_score: float | None
    max_epss_score: float | None
    # Per-finding threat score over this scan, not the dashboard's same-named project exposure score.
    avg_risk_score: float | None
    max_risk_score: float | None
    kev_details: list[KEVDetail]
    # high_risk_cves is the top-scoring sample; high_risk_total is how many cleared the threshold.
    high_risk_cves: list[HighRiskCVE]
    high_risk_total: int
    high_risk_threshold: float
    timestamp: str


class ReachabilityLevelCounts(TypedDict):
    confirmed: int  # Symbol-level match
    likely: int  # Import-level match
    unknown: int
    unreachable: int


class CallgraphInfo(TypedDict):
    language: str
    total_modules: int
    total_imports: int
    # Size of the coverage universe: packages the producer resolved and inspected.
    coverage_modules: int
    generated_at: str | None


class VulnerabilityInfo(TypedDict, total=False):
    cve: str
    component: str
    version: str
    severity: str
    reachability_level: str
    reachable_functions: list[str]
    is_high_confidence: bool


class ReachabilitySummary(TypedDict):
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
