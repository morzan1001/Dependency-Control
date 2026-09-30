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
    deps_dev: dict[str, Any] = Field(default_factory=dict)

    description: str | None = None

    sources: list[str] = Field(default_factory=list)

    def to_mongo_dict(self) -> dict[str, Any]:
        """Convert to a sparse dict for MongoDB storage (no None values)."""
        result = self._license_fields()

        if self.homepage:
            result["homepage"] = self.homepage
        if self.repository_url:
            result["repository_url"] = self.repository_url

        if self.deps_dev:
            result["deps_dev"] = self.deps_dev

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
