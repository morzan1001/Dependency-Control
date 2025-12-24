from typing import Optional
from pydantic import BaseModel, Field


class ThreatIntelligenceStats(BaseModel):
    """Statistics from EPSS/KEV enrichment."""
    kev_count: int = Field(0, description="Count of findings in CISA KEV catalog")
    kev_ransomware_count: int = Field(0, description="Count of KEV findings with known ransomware use")
    high_epss_count: int = Field(0, description="Count of findings with EPSS > 10%")
    medium_epss_count: int = Field(0, description="Count of findings with EPSS 1-10%")
    avg_epss_score: Optional[float] = Field(None, description="Average EPSS score")
    max_epss_score: Optional[float] = Field(None, description="Maximum EPSS score")
    weaponized_count: int = Field(0, description="Count of weaponized vulnerabilities")
    active_exploitation_count: int = Field(0, description="Count of actively exploited vulnerabilities")


class ReachabilityStats(BaseModel):
    """Statistics from reachability analysis."""
    analyzed_count: int = Field(0, description="Count of vulnerabilities analyzed for reachability")
    reachable_count: int = Field(0, description="Count of confirmed reachable vulnerabilities")
    likely_reachable_count: int = Field(0, description="Count of likely reachable vulnerabilities")
    unreachable_count: int = Field(0, description="Count of unreachable vulnerabilities")
    unknown_count: int = Field(0, description="Count of vulnerabilities with unknown reachability")
    reachable_critical: int = Field(0, description="Critical vulns that are reachable")
    reachable_high: int = Field(0, description="High vulns that are reachable")


class PrioritizedCounts(BaseModel):
    """Vulnerability counts with intelligent prioritization."""
    # Traditional severity counts
    total: int = Field(0, description="Total vulnerability count")
    critical: int = Field(0, description="Critical severity count")
    high: int = Field(0, description="High severity count")
    medium: int = Field(0, description="Medium severity count")
    low: int = Field(0, description="Low severity count")
    
    # Actionable/Priority counts (the ones you should focus on)
    actionable_critical: int = Field(0, description="Critical vulns that are exploitable AND reachable")
    actionable_high: int = Field(0, description="High vulns that are exploitable AND reachable")
    actionable_total: int = Field(0, description="Total actionable vulns (KEV/high-EPSS AND reachable)")
    
    # Deprioritized counts (vulns you can safely defer)
    deprioritized_count: int = Field(0, description="Vulns that are unreachable or low-EPSS without KEV")


class Stats(BaseModel):
    critical: int = Field(0, description="Count of critical findings")
    high: int = Field(0, description="Count of high severity findings")
    medium: int = Field(0, description="Count of medium severity findings")
    low: int = Field(0, description="Count of low severity findings")
    info: int = Field(0, description="Count of informational findings")
    unknown: int = Field(0, description="Count of findings with unknown severity")
    risk_score: float = Field(0.0, description="Calculated risk score (0-100)")
    
    # Adjusted risk score considering EPSS, KEV, and Reachability
    adjusted_risk_score: float = Field(0.0, description="Risk score adjusted for exploitability and reachability")
    
    # Threat intelligence stats
    threat_intel: Optional[ThreatIntelligenceStats] = Field(None, description="EPSS/KEV statistics")
    
    # Reachability stats  
    reachability: Optional[ReachabilityStats] = Field(None, description="Reachability analysis statistics")
    
    # Prioritized counts
    prioritized: Optional[PrioritizedCounts] = Field(None, description="Intelligently prioritized vulnerability counts")

