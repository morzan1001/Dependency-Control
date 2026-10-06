"""Typed contracts for ``Finding.details`` payloads, one model per finding type.

Writers (normalizers/analyzers) construct these models and store
``model_dump(exclude_none=True)``; readers may only consume keys declared here.
``tests/schemas/test_finding_details_contract.py`` walks the backend source and
fails on any ``details`` key that no model declares, so writer/reader drift is a
test failure instead of a silently-empty feature.

``extra="allow"`` keeps analyzer-specific extras round-tripping through
re-validation; it does not exempt readers from declaring what they consume.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class _DetailsModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ScorecardContext(_DetailsModel):
    """Cross-link block from a package's quality aggregate onto its other findings (``aggregation.cross_link``)."""

    overall_score: float | None = None
    project_url: str | None = None
    critical_issues: list[str] = []
    maintenance_risk: bool = False
    has_vulnerabilities_issue: bool = False


class LineSpan(_DetailsModel):
    line: int | None = None
    column: int | None = None


class ReachabilityInfo(_DetailsModel):
    """Written by ``reachability_enrichment`` under ``details.reachability``."""

    is_reachable: bool | None = None
    confidence_score: float | None = None
    analysis_level: str | None = None
    matched_symbols: list[Any] = []
    # The two lists are samples; the counts beside them are the totals they were cut from.
    import_locations: list[Any] = []
    import_location_count: int | None = None
    vulnerable_symbols: list[Any] = []
    vulnerable_symbol_count: int | None = None
    message: str | None = None


class OutdatedInfo(_DetailsModel):
    """Cross-link block on vulnerability findings (``aggregation.cross_link``)."""

    is_outdated: bool = True
    current_version: str | None = None
    latest_version: str | None = None
    message: str | None = None


class QualityInfo(_DetailsModel):
    has_quality_issues: bool = True
    issue_count: int | None = None
    has_maintenance_issues: bool = False


class LicenseInfo(_DetailsModel):
    has_license_issue: bool = True
    license: str | None = None
    category: str | None = None
    license_severity: str | None = None


class EolInfo(_DetailsModel):
    is_eol: bool = True
    eol_date: Any = None
    cycle: Any = None
    latest_version: Any = None


class VulnerabilityContextInfo(_DetailsModel):
    """Cross-link block on non-vulnerability findings (``aggregation.cross_link``)."""

    has_vulnerabilities: bool = True
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0


class AdditionalFindingType(_DetailsModel):
    """One entry of ``details.additional_finding_types``: another type on the same package."""

    type: str
    severity: str


class VulnerabilityScannerDetails(_DetailsModel):
    """Per-scanner details of a single vulnerability (trivy/grype/osv), nested in
    ``details.vulnerabilities[].details``."""

    fixed_version: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[Any] | None = None
    cwe_ids: list[str] | None = None
    published_date: str | None = None
    last_modified_date: str | None = None
    # trivy
    layer_id: str | None = None
    # grype
    datasource: str | None = None
    namespace: str | None = None
    # osv
    osv_url: str | None = None
    ecosystem_specific: dict[str, Any] | None = None


class VulnerabilityEntryDetails(_DetailsModel):
    """One entry of ``details.vulnerabilities`` on an aggregated vulnerability finding."""

    id: str | None = None
    severity: str | None = None
    description: str | None = None
    fixed_version: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[Any] = []
    aliases: list[str] = []
    scanners: list[str] = []
    details: VulnerabilityScannerDetails | None = None
    ecosystem_specific: dict[str, Any] | None = None
    # enrichment (enrichment.service)
    epss_score: float | None = None
    epss_percentile: float | None = None
    in_kev: bool | None = None
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_required_action: str | None = None
    kev_ransomware_use: bool | None = None
    exploit_maturity: str | None = None
    risk_score: float | None = None
    github_advisory_url: str | None = None
    resolved_cve: str | None = None
    # per-entry waiver state (services.waivers.apply.restamp_waivers)
    waived: bool | None = None
    waiver_reason: str | None = None
    # earliest detection on the component in the project, any version (analysis.engine._stamp_first_seen)
    first_seen_at: datetime | None = None


class VulnerabilityDetails(_DetailsModel):
    """Aggregated vulnerability finding: entry list plus finding-level enrichment."""

    vulnerabilities: list[VulnerabilityEntryDetails] = []
    fixed_version: str | None = None
    # enrichment (enrichment.service)
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None
    in_kev: bool | None = None
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_required_action: str | None = None
    kev_ransomware_use: bool | None = None
    exploit_maturity: str | None = None
    risk_score: float | None = None
    github_advisory_url: str | None = None
    # reachability (reachability_enrichment)
    reachability: ReachabilityInfo | None = None
    adjusted_risk_score: float | None = None
    # cross-links (aggregation.cross_link)
    outdated_info: OutdatedInfo | None = None
    quality_info: QualityInfo | None = None
    license_info: LicenseInfo | None = None
    eol_info: EolInfo | None = None
    additional_finding_types: list[AdditionalFindingType] = []
    scorecard_context: ScorecardContext | None = None


class LicenseDetails(_DetailsModel):
    license: str | None = None
    license_url: str | None = None
    category: str | None = None
    explanation: str | None = None
    recommendation: str | None = None
    obligations: list[Any] = []
    risks: list[Any] = []
    purl: str | None = None
    spdx_expression: str | None = None
    context_reason: str | None = None
    severity_without_context: str | None = None
    additional_finding_types: list[AdditionalFindingType] = []
    vulnerability_info: VulnerabilityContextInfo | None = None
    scorecard_context: ScorecardContext | None = None


class SecretDetails(_DetailsModel):
    detector: str
    detector_name: str | None = None
    decoder: str | None = None
    verified: bool | None = None
    redacted: str | None = None
    commit: str | None = None
    commit_timestamp: str | None = None
    line: int | None = None
    in_current_tree: bool | None = None
    risk_score: float
    adjusted_risk_score: float


class EolDetails(_DetailsModel):
    # endoflife.date payloads mix strings, numbers, and booleans across products.
    fixed_version: Any = None
    eol_date: Any = None
    cycle: Any = None
    recommended_cycle: Any = None
    link: str | None = None
    lts: Any = None
    additional_finding_types: list[AdditionalFindingType] = []
    vulnerability_info: VulnerabilityContextInfo | None = None
    scorecard_context: ScorecardContext | None = None


class OutdatedDetails(_DetailsModel):
    fixed_version: str | None = None
    default_version: str | None = None
    ahead_of_default: bool | None = None
    additional_finding_types: list[AdditionalFindingType] = []
    vulnerability_info: VulnerabilityContextInfo | None = None
    scorecard_context: ScorecardContext | None = None


class ScorecardIssueDetails(_DetailsModel):
    """Details of a single scorecard quality issue (normalize_scorecard)."""

    scorecard: dict[str, Any] = {}
    overall_score: float | None = None
    failed_checks: list[Any] = []
    critical_issues: list[str] = []
    project_url: str | None = None
    repository: str | None = None
    scorecard_date: str | None = None
    recommendation: str | None = None
    checks_summary: dict[Any, Any] = {}


class MaintainerRiskDetails(_DetailsModel):
    """Details of a single maintainer-risk quality issue (normalize_maintainer_risk)."""

    risks: list[Any] = []
    maintainer_info: dict[str, Any] = {}
    risk_count: int | None = None


class QualityIssueEntry(_DetailsModel):
    """One entry of ``details.quality_issues`` on an aggregated quality finding."""

    id: str | None = None
    type: str | None = None
    severity: str | None = None
    description: str | None = None
    scanners: list[str] = []
    details: dict[str, Any] = {}


class QualityDetails(_DetailsModel):
    quality_issues: list[QualityIssueEntry] = []
    overall_score: float | None = None
    has_maintenance_issues: bool = False
    issue_count: int | None = None
    additional_finding_types: list[AdditionalFindingType] = []
    vulnerability_info: VulnerabilityContextInfo | None = None


class SastScannerDetails(_DetailsModel):
    """Per-scanner SAST details (opengrep/bearer); also the shape of
    ``crypto_key_management`` findings and of ``details.sast_findings[].details``."""

    rule_id: str | None = None
    check_id: str | None = None
    title: str | None = None
    code_extract: str | None = None
    start: LineSpan | None = None
    end: LineSpan | None = None
    cwe_ids: list[str] = []
    owasp: list[str] | None = None
    impact: str | None = None
    confidence: str | None = None
    likelihood: str | None = None
    category: str | None = None
    category_groups: list[Any] = []
    subcategory: list[str] | None = None
    technology: list[str] | None = None
    vulnerability_class: list[str] | None = None
    references: list[Any] = []
    source_rule_url: str | None = None
    source: Any = None
    shortlink: str | None = None
    license: str | None = None
    fingerprint: str | None = None
    documentation_url: str | None = None


class SastFindingEntry(_DetailsModel):
    """One entry of ``details.sast_findings`` on a merged SAST finding."""

    id: str | None = None
    scanner: str | None = None
    severity: str | None = None
    details: SastScannerDetails | None = None


class SastDetails(_DetailsModel):
    """SAST finding as persisted (aggregation.merging.to_sast_aggregate)."""

    sast_findings: list[SastFindingEntry] = []
    file: str | None = None
    line: int | None = None


class IacDetails(_DetailsModel):
    rule_id: str | None = None
    title: str | None = None
    start: LineSpan | None = None
    end: LineSpan | None = None
    category: str | None = None
    platform: str | None = None
    actual_value: Any = None
    expected_value: Any = None
    search_key: str | None = None
    similarity_id: str | None = None
    code_extract: str | None = None
    cwe_ids: list[str] = []
    documentation_url: str | None = None
    references: list[Any] = []


class TyposquattingDetails(_DetailsModel):
    imitated_package: str | None = None
    similarity: float | None = None
    additional_finding_types: list[AdditionalFindingType] = []
    vulnerability_info: VulnerabilityContextInfo | None = None
    scorecard_context: ScorecardContext | None = None


class OsvMalwareDetails(_DetailsModel):
    osv_id: str | None = None
    source: str | None = None
    reference: str | None = None
    references: list[str] = []
    published: str | None = None
    modified: str | None = None
    affected_versions: list[str] = []
    osv_url: str | None = None


class OsMalwareDetails(_DetailsModel):
    # info carries the raw OpenSourceMalware report block; analyzer-specific passthrough.
    info: dict[str, Any] = {}
    threats: Any = None
    reference: str | None = None
    source: str | None = None


class HashVerificationDetails(_DetailsModel):
    registry: str | None = None
    algorithm: str | None = None
    sbom_hash: str | None = None
    expected_hashes: list[Any] = []
    verification_failed: bool = True


class SystemWarningDetails(_DetailsModel):
    # Failed analyzers report strings; malformed external results can carry structured blobs.
    error_details: Any = None
    errors: list[dict[str, Any]] = []


class MatchedRuleEntry(_DetailsModel):
    """One entry of ``details.matched_rules`` on a crypto policy-rule finding."""

    rule_id: str | None = None
    rule_name: str | None = None
    policy_source: str | None = None
    severity: str | None = None


class CryptoRuleDetails(_DetailsModel):
    """Details for crypto_weak_algorithm / crypto_weak_key / crypto_quantum_vulnerable."""

    rule_id: str | None = None
    rule_name: str | None = None
    policy_source: str | None = None
    matched_rules: list[MatchedRuleEntry] = []
    bom_ref: str | None = None
    asset_name: str | None = None
    asset_type: str | None = None
    key_size_bits: int | None = None
    primitive: str | None = None
    references: list[Any] = []
    occurrence_count: int | None = None


def all_rule_ids(details: Mapping[str, Any] | None) -> set[str]:
    """Every rule a crypto finding belongs to: the lead rule_id plus each matched_rules entry."""
    details = details or {}
    ids = {entry["rule_id"] for entry in details.get("matched_rules") or [] if entry.get("rule_id")}
    if lead := details.get("rule_id"):
        ids.add(lead)
    return ids


class CryptoCertificateDetails(_DetailsModel):
    """Details for the crypto_cert_* finding family (certificate_lifecycle checks)."""

    bom_ref: str | None = None
    subject_name: str | None = None
    issuer_name: str | None = None
    days_expired: int | None = None
    not_valid_after: str | None = None
    days_until_expiry: int | None = None
    days_until_valid: int | None = None
    not_valid_before: str | None = None
    algorithm_name: str | None = None
    related_algo_bom_ref: str | None = None
    key_size_bits: int | None = None
    min_key_size_bits: int | None = None
    validity_days: int | None = None
    threshold: int | None = None
    rule_id: str | None = None
    matched_rules: list[MatchedRuleEntry] | None = None
    occurrence_count: int | None = None


class CryptoProtocolDetails(_DetailsModel):
    """Details for crypto_weak_protocol findings (protocol_cipher analyzer)."""

    bom_ref: str | None = None
    protocol_type: str | None = None
    protocol_version: str | None = None
    cipher_suite: str | None = None
    cipher_suite_value: Any = None
    key_exchange: str | None = None
    authentication: str | None = None
    cipher: str | None = None
    mac: str | None = None
    weakness_tags: list[str] = []
    catalog_version: int | str | None = None
    rule_id: str | None = None
    matched_rules: list[MatchedRuleEntry] | None = None
    occurrence_count: int | None = None
