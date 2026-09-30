"""Models for aggregating dependency enrichment data from multiple sources."""

from typing import Any

from pydantic import BaseModel, Field, computed_field

from app.core.constants import ExploitMaturity


class EPSSData(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data for a CVE."""

    cve: str
    epss_score: float  # probability of exploitation in next 30 days (0.0 - 1.0)
    percentile: float
    date: str


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
    cve_id: str | None = None
    summary: str | None = None
    severity: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    withdrawn_at: str | None = None
    github_url: str = ""
    aliases: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def advisory_url(self) -> str:
        if self.github_url:
            return self.github_url
        return f"https://github.com/advisories/{self.ghsa_id}"


class VulnerabilityEnrichment(BaseModel):
    """Enriched vulnerability data combining multiple sources."""

    cve: str

    epss_score: float | None = None  # 0.0 - 1.0
    epss_percentile: float | None = None  # 0.0 - 100.0
    epss_date: str | None = None

    is_kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_required_action: str | None = None
    kev_ransomware_use: bool = False

    exploit_maturity: ExploitMaturity = "unknown"
    risk_score: float  # 0-100


class DependencyEnrichment(BaseModel):
    """Enrichment data for a dependency merged from SBOM, deps.dev and the license scanner."""

    name: str
    version: str
    # Canonical purl (qualifiers/subpath stripped) — the cross-scan join key.
    purl: str | None = None

    licenses: list[dict[str, Any]] = Field(default_factory=list)  # [{spdx_id, source, category, ...}]
    primary_license: str | None = None
    # Raw SBOM-declared SPDX expression when composite (e.g. "A AND (B WITH exception)").
    license_expression: str | None = None
    license_category: str | None = None  # permissive, copyleft, etc.
    license_risks: list[str] = Field(default_factory=list)
    license_obligations: list[str] = Field(default_factory=list)

    homepage: str | None = None
    repository_url: str | None = None
    documentation_url: str | None = None
    issues_url: str | None = None
    changelog_url: str | None = None
    additional_links: dict[str, str] = Field(default_factory=dict)

    project_url: str | None = None
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    dependents_total: int | None = None
    dependents_direct: int | None = None
    dependents_indirect: int | None = None

    scorecard_score: float | None = None
    scorecard_date: str | None = None
    scorecard_checks_count: int | None = None

    published_at: str | None = None
    is_deprecated: bool = False

    known_advisories: list[str] = Field(default_factory=list)
    has_attestations: bool = False
    has_slsa_provenance: bool = False

    description: str | None = None

    sources: list[str] = Field(default_factory=list)

    def to_mongo_dict(self) -> dict[str, Any]:
        """Convert to a sparse dict for MongoDB storage (no None values)."""
        result = self._license_fields()

        if self.homepage:
            result["homepage"] = self.homepage
        if self.repository_url:
            result["repository_url"] = self.repository_url

        deps_dev = self._deps_dev_fields()
        if deps_dev:
            result["deps_dev"] = deps_dev

        if self.description:
            result["description"] = self.description

        if self.sources:
            result["enrichment_sources"] = self.sources

        return result

    def _license_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.primary_license:
            fields["license"] = self.primary_license
        if self.license_expression:
            fields["license_expression"] = self.license_expression
        if self.license_category:
            fields["license_category"] = self.license_category
        if self.licenses:
            fields["licenses_detailed"] = self.licenses
        if self.license_risks:
            fields["license_risks"] = self.license_risks
        if self.license_obligations:
            fields["license_obligations"] = self.license_obligations
        return fields

    def _deps_dev_fields(self) -> dict[str, Any]:
        deps_dev: dict[str, Any] = {}
        if self.project_url:
            deps_dev["project_url"] = self.project_url
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
                "indirect": self.dependents_indirect,
            }

        if self.scorecard_score is not None:
            deps_dev["scorecard"] = {
                "overall_score": self.scorecard_score,
                "date": self.scorecard_date,
                "checks_count": self.scorecard_checks_count,
            }

        links = self._deps_dev_links()
        if links:
            deps_dev["links"] = links

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
        return deps_dev

    def _deps_dev_links(self) -> dict[str, str]:
        links: dict[str, str] = {}
        if self.documentation_url:
            links["documentation"] = self.documentation_url
        if self.issues_url:
            links["issues"] = self.issues_url
        if self.changelog_url:
            links["changelog"] = self.changelog_url
        links.update(self.additional_links)
        return links
