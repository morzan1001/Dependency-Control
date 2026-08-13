from pydantic import BaseModel, Field


class ThreatIntelligenceStats(BaseModel):
    """Statistics from EPSS/KEV enrichment."""

    kev_count: int = Field(0, description="Count of findings in CISA KEV catalog")
    kev_ransomware_count: int = Field(0, description="Count of KEV findings with known ransomware use")
    high_epss_count: int = Field(0, description="Count of findings with EPSS > 10%")
    medium_epss_count: int = Field(0, description="Count of findings with EPSS 1-10%")
    avg_epss_score: float | None = Field(None, description="Average EPSS score")
    max_epss_score: float | None = Field(None, description="Maximum EPSS score")
    weaponized_count: int = Field(0, description="Count of weaponized vulnerabilities")
    active_exploitation_count: int = Field(0, description="Count of actively exploited vulnerabilities")


class ReachabilityStats(BaseModel):
    """Reachability analysis statistics; prefer the ``*_high_confidence`` fields for headline numbers."""

    analyzed_count: int = Field(0, description="Count of vulnerabilities analyzed for reachability")
    reachable_count: int = Field(
        0, description="Count of reachable vulnerabilities (total = confirmed symbol-level + likely import-level)"
    )
    confirmed_reachable_count: int = Field(
        0,
        description="Count of confirmed (symbol-level) reachable vulnerabilities — the strong subset of reachable_count",
    )
    likely_reachable_count: int = Field(
        0, description="Count of likely (import-level) reachable vulnerabilities — the weaker subset of reachable_count"
    )
    unreachable_count: int = Field(0, description="Count of unreachable vulnerabilities")
    unknown_count: int = Field(0, description="Count of vulnerabilities with unknown reachability")
    reachable_critical: int = Field(0, description="Critical vulns that are reachable")
    reachable_high: int = Field(0, description="High vulns that are reachable")
    reachable_count_high_confidence: int = Field(0, description="Reachable vulns above the high-confidence threshold")
    reachable_critical_high_confidence: int = Field(0, description="Critical vulns reachable with high confidence")
    reachable_high_high_confidence: int = Field(0, description="High-severity vulns reachable with high confidence")


class PrioritizedCounts(BaseModel):
    """Vulnerability counts focused on exploitability + reachability."""

    total: int = Field(0, description="Total vulnerability count")
    critical: int = Field(0, description="Critical severity count")
    high: int = Field(0, description="High severity count")
    medium: int = Field(0, description="Medium severity count")
    low: int = Field(0, description="Low severity count")

    actionable_critical: int = Field(0, description="Critical vulns that are exploitable AND reachable")
    actionable_high: int = Field(0, description="High vulns that are exploitable AND reachable")
    actionable_total: int = Field(0, description="Total actionable vulns (KEV/high-EPSS AND reachable)")

    deprioritized_count: int = Field(0, description="Vulns that are unreachable or low-EPSS without KEV")


class SecretPrioritizedCounts(BaseModel):
    """Secret finding counts focused on git-context-aware priorisation."""

    total: int = Field(0, description="Total secret finding count")
    verified_count: int = Field(0, description="Secrets TruffleHog confirmed as live/valid")
    in_current_tree_count: int = Field(0, description="Secrets whose file exists at the scanned commit's tree")
    historical_only_count: int = Field(0, description="Secrets whose file no longer exists in the current tree")
    unknown_tree_count: int = Field(0, description="Secrets with no current-tree information available")
    actionable_count: int = Field(0, description="Verified secrets still present in the current tree")
    deprioritized_count: int = Field(0, description="Unverified secrets no longer present in the current tree")


class Stats(BaseModel):
    critical: int = Field(0, description="Count of critical findings")
    high: int = Field(0, description="Count of high severity findings")
    medium: int = Field(0, description="Count of medium severity findings")
    low: int = Field(0, description="Count of low severity findings")
    negligible: int = Field(0, description="Count of negligible severity findings")
    info: int = Field(0, description="Count of informational findings")
    unknown: int = Field(0, description="Count of findings with unknown or unmapped severity")
    risk_score: float = Field(
        0.0,
        description=(
            "Saturating severity-weighted exposure score on a 0-100 scale: "
            "100*E/(E+RISK_SCORE_HALF_SATURATION) with E the "
            "RISK_SEVERITY_WEIGHTS-weighted sum of CRITICAL/HIGH/MEDIUM/LOW "
            "finding counts. Monotone in the finding set; INFO/UNKNOWN/"
            "NEGLIGIBLE findings do not contribute."
        ),
    )
    adjusted_risk_score: float = Field(
        0.0,
        description=(
            "Reachability-adjusted score on the SAME saturating 0-100 scale as "
            "risk_score: each finding's severity weight is scaled x0.4 if "
            "unreachable and x1.1 if confirmed (symbol-level) reachable."
        ),
    )

    threat_intel: ThreatIntelligenceStats | None = Field(None, description="EPSS/KEV statistics")
    reachability: ReachabilityStats | None = Field(None, description="Reachability analysis statistics")
    prioritized: PrioritizedCounts | None = Field(None, description="Prioritized vulnerability counts")
    secret_priority: SecretPrioritizedCounts | None = Field(None, description="Prioritized secret finding counts")
