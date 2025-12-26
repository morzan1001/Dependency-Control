"""
Dependency Enrichment Schema Definitions

Data classes for aggregating enrichment data from multiple sources:
- SBOM (base dependency data)
- deps.dev (external metadata, scorecard, links)
- license_compliance scanner (detailed license analysis)
- EPSS/KEV (vulnerability exploitation data)
- Reachability analysis (vulnerable code paths)
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, computed_field

# =============================================================================
# EPSS/KEV Enrichment Schemas
# =============================================================================


class EPSSData(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data for a CVE."""

    cve: str
    epss_score: float  # Probability of exploitation in next 30 days (0.0 - 1.0)
    percentile: float  # Percentile rank among all CVEs
    date: str  # Date of the EPSS calculation


class KEVEntry(BaseModel):
    """CISA Known Exploited Vulnerability entry."""

    cve: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: bool = False


class GHSAData(BaseModel):
    """GitHub Security Advisory data."""

    ghsa_id: str
    cve_id: Optional[str] = None  # Resolved CVE ID if available
    summary: Optional[str] = None
    severity: Optional[str] = None
    published_at: Optional[str] = None
    updated_at: Optional[str] = None
    withdrawn_at: Optional[str] = None
    github_url: str = ""  # Direct link to GitHub Advisory
    aliases: List[str] = Field(default_factory=list)  # All related IDs (CVEs, etc.)

    @computed_field
    @property
    def advisory_url(self) -> str:
        """Get the GitHub Advisory URL."""
        if self.github_url:
            return self.github_url
        return f"https://github.com/advisories/{self.ghsa_id}"


class VulnerabilityEnrichment(BaseModel):
    """Enriched vulnerability data combining multiple sources."""

    cve: str

    # EPSS Data
    epss_score: Optional[float] = None  # 0.0 - 1.0, probability of exploitation
    epss_percentile: Optional[float] = None  # 0.0 - 100.0
    epss_date: Optional[str] = None

    # CISA KEV Data
    is_kev: bool = False  # Is in CISA Known Exploited Vulnerabilities catalog
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_required_action: Optional[str] = None
    kev_ransomware_use: bool = False

    # Computed fields
    exploit_maturity: str = "unknown"  # unknown, poc, active, weaponized
    risk_score: Optional[float] = None  # Combined risk score 0-100


# =============================================================================
# Reachability Analysis Schemas
# =============================================================================


class ExtractedSymbols(BaseModel):
    """Result of symbol extraction from a vulnerability."""

    cve: str
    package: str
    symbols: List[str] = Field(default_factory=list)
    confidence: str = "low"  # low, medium, high
    extraction_method: str = "none"  # none, regex, osv_ecosystem
    raw_text: Optional[str] = None  # The text we parsed


# =============================================================================
# Dependency Enrichment Schemas
# =============================================================================


class DependencyEnrichment(BaseModel):
    """
    Aggregated enrichment data for a dependency from multiple sources.
    This creates a single source of truth by merging data from:
    - SBOM (base data)
    - deps.dev (external metadata, scorecard, links)
    - license_compliance scanner (detailed license analysis)
    """

    name: str
    version: str

    # License info (aggregated from multiple sources)
    licenses: List[Dict[str, Any]] = Field(
        default_factory=list
    )  # [{spdx_id, source, category, ...}]
    primary_license: Optional[str] = None  # Best determined license
    license_category: Optional[str] = None  # permissive, copyleft, etc.
    license_risks: List[str] = Field(default_factory=list)
    license_obligations: List[str] = Field(default_factory=list)

    # Links (aggregated from SBOM + deps.dev)
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    documentation_url: Optional[str] = None
    issues_url: Optional[str] = None
    changelog_url: Optional[str] = None
    download_url: Optional[str] = None
    additional_links: Dict[str, str] = Field(default_factory=dict)

    # Project metrics (from deps.dev)
    stars: Optional[int] = None
    forks: Optional[int] = None
    open_issues: Optional[int] = None
    dependents_total: Optional[int] = None
    dependents_direct: Optional[int] = None

    # Scorecard (from deps.dev)
    scorecard_score: Optional[float] = None
    scorecard_date: Optional[str] = None
    scorecard_checks_count: Optional[int] = None
    scorecard_checks: List[Dict[str, Any]] = Field(default_factory=list)
    scorecard_critical_issues: List[str] = Field(default_factory=list)

    # Version/Publication info
    published_at: Optional[str] = None
    is_deprecated: bool = False
    is_default_version: bool = False

    # Security indicators
    known_advisories: List[str] = Field(default_factory=list)
    has_attestations: bool = False
    has_slsa_provenance: bool = False

    # Description (prefer deps.dev over SBOM if more detailed)
    description: Optional[str] = None

    # Source tracking
    sources: List[str] = Field(default_factory=list)  # Which scanners contributed

    def to_mongo_dict(self) -> Dict[str, Any]:
        """Convert to dictionary optimized for MongoDB storage (sparse, no None values)."""
        result: Dict[str, Any] = {}

        # License aggregation
        if self.primary_license:
            result["license"] = self.primary_license
        if self.license_category:
            result["license_category"] = self.license_category
        if self.licenses:
            result["licenses_detailed"] = self.licenses
        if self.license_risks:
            result["license_risks"] = self.license_risks
        if self.license_obligations:
            result["license_obligations"] = self.license_obligations

        # Links - update only if we have better data
        if self.homepage:
            result["homepage"] = self.homepage
        if self.repository_url:
            result["repository_url"] = self.repository_url
        if self.download_url:
            result["download_url"] = self.download_url

        # deps.dev specific enrichment
        deps_dev: Dict[str, Any] = {}
        if self.stars is not None:
            deps_dev["stars"] = self.stars
        if self.forks is not None:
            deps_dev["forks"] = self.forks
        if self.open_issues is not None:
            deps_dev["open_issues"] = self.open_issues
        if self.dependents_total is not None:
            deps_dev["dependents"] = {
                "total": self.dependents_total,
                "direct": self.dependents_direct,
            }

        # Scorecard
        if self.scorecard_score is not None:
            deps_dev["scorecard"] = {
                "overall_score": self.scorecard_score,
                "date": self.scorecard_date,
                "checks_count": self.scorecard_checks_count,
            }

        # Additional links from deps.dev
        if (
            self.documentation_url
            or self.issues_url
            or self.changelog_url
            or self.additional_links
        ):
            deps_dev["links"] = {}
            if self.documentation_url:
                deps_dev["links"]["documentation"] = self.documentation_url
            if self.issues_url:
                deps_dev["links"]["issues"] = self.issues_url
            if self.changelog_url:
                deps_dev["links"]["changelog"] = self.changelog_url
            deps_dev["links"].update(self.additional_links)

        # Publication info
        if self.published_at:
            deps_dev["published_at"] = self.published_at
        if self.is_deprecated:
            deps_dev["is_deprecated"] = True
        if self.known_advisories:
            deps_dev["known_advisories"] = self.known_advisories
        if self.has_attestations:
            deps_dev["has_attestations"] = True
        if self.has_slsa_provenance:
            deps_dev["has_slsa_provenance"] = True

        if deps_dev:
            result["deps_dev"] = deps_dev

        # Description override
        if self.description:
            result["description"] = self.description

        # Metadata
        if self.sources:
            result["enrichment_sources"] = self.sources

        return result
