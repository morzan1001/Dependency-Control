"""
Dependency Enrichment Schema Definitions

Data classes for aggregating enrichment data from multiple sources:
- SBOM (base dependency data)
- deps.dev (external metadata, scorecard, links)
- license_compliance scanner (detailed license analysis)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class DependencyEnrichment:
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
    licenses: List[Dict[str, Any]] = field(
        default_factory=list
    )  # [{spdx_id, source, category, ...}]
    primary_license: Optional[str] = None  # Best determined license
    license_category: Optional[str] = None  # permissive, copyleft, etc.
    license_risks: List[str] = field(default_factory=list)
    license_obligations: List[str] = field(default_factory=list)

    # Links (aggregated from SBOM + deps.dev)
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    documentation_url: Optional[str] = None
    issues_url: Optional[str] = None
    changelog_url: Optional[str] = None
    download_url: Optional[str] = None
    additional_links: Dict[str, str] = field(default_factory=dict)

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
    scorecard_checks: List[Dict[str, Any]] = field(default_factory=list)
    scorecard_critical_issues: List[str] = field(default_factory=list)

    # Version/Publication info
    published_at: Optional[str] = None
    is_deprecated: bool = False
    is_default_version: bool = False

    # Security indicators
    known_advisories: List[str] = field(default_factory=list)
    has_attestations: bool = False
    has_slsa_provenance: bool = False

    # Description (prefer deps.dev over SBOM if more detailed)
    description: Optional[str] = None

    # Source tracking
    sources: Set[str] = field(default_factory=set)  # Which scanners contributed

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MongoDB storage."""
        result = {}

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
        deps_dev = {}
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
            result["enrichment_sources"] = list(self.sources)

        return result
