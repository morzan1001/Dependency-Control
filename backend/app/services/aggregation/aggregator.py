"""ResultAggregator - aggregates findings from multiple analyzers."""

import re
from collections import Counter
from typing import Any

from app.core.constants import (
    AGG_KEY_QUALITY,
    AGG_KEY_VULNERABILITY,
    MAX_CROSS_LINK_GROUP_SIZE,
    UNKNOWN_LICENSE_PATTERNS,
)
from app.models.finding import PACKAGE_FINDING_TYPES, Finding, FindingType, Severity
from app.models.license import CATEGORY_RESTRICTIVENESS
from app.schemas.enrichment import DependencyEnrichment
from app.schemas.finding import (
    QualityAggregatedDetails,
    QualityEntry,
    VulnerabilityAggregatedDetails,
    VulnerabilityEntry,
)
from app.schemas.finding_details import SystemWarningDetails
from app.services.component_identity import (
    cluster_by_package_identity,
    extract_artifact_name,
    normalize_component,
)
from app.services.aggregation.cross_link import cross_link_pair, record_additional_types
from app.services.aggregation.merging import (
    absorb_header,
    dedupe_vulnerability_entries,
    merge_findings_data,
    to_sast_aggregate,
)
from app.services.aggregation.quality import update_quality_description
from app.services.aggregation.versions import aggregate_fixed_version, normalize_version
from app.services.analyzers.license_compliance.constants import LICENSE_DATABASE
from app.services.analyzers.license_compliance.normalizer import (
    normalize_license as normalize_spdx_id,
)
from app.services.analyzers.license_compliance.normalizer import (
    tokenize_license_string,
)
from app.services.analyzers.maintainer_risk import MAINTENANCE_RISK_TYPES
from app.core.purl import canonical_purl
from app.services.normalizers.crypto import normalize_crypto
from app.services.normalizers.iac import normalize_kics
from app.services.normalizers.license import normalize_license
from app.services.normalizers.lifecycle import normalize_eol, normalize_outdated
from app.services.normalizers.quality import (
    normalize_maintainer_risk,
    normalize_scorecard,
    normalize_typosquatting,
)
from app.services.normalizers.sast import normalize_bearer, normalize_opengrep
from app.services.normalizers.utils import FindingIdPrefix
from app.services.normalizers.secret import normalize_trufflehog
from app.services.normalizers.security import (
    normalize_hash_verification,
    normalize_malware,
)
from app.services.normalizers.vulnerability import (
    normalize_grype,
    normalize_osv,
    normalize_trivy,
)
from app.services.waivers.signature import compute_match_signature

_LICENSE_SENTINELS = UNKNOWN_LICENSE_PATTERNS | {"NON-STANDARD"}
_SPDX_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_ENTRY_LEVEL_KEYS = frozenset({"ecosystem_specific", "fixed_version", "cvss_score", "cvss_vector", "references"})
_NORMALIZERS = {
    "trivy": normalize_trivy,
    "grype": normalize_grype,
    "osv": normalize_osv,
    "outdated_packages": normalize_outdated,
    "license_compliance": normalize_license,
    "deps_dev": normalize_scorecard,
    "os_malware": normalize_malware,
    "end_of_life": normalize_eol,
    "typosquatting": normalize_typosquatting,
    "trufflehog": normalize_trufflehog,
    "opengrep": normalize_opengrep,
    "kics": normalize_kics,
    "bearer": normalize_bearer,
    "hash_verification": normalize_hash_verification,
    "maintainer_risk": normalize_maintainer_risk,
    "crypto_weak_algorithm": normalize_crypto,
    "crypto_weak_key": normalize_crypto,
    "crypto_quantum_vulnerable": normalize_crypto,
    "crypto_certificate_lifecycle": normalize_crypto,
    "crypto_protocol_cipher": normalize_crypto,
}


def _package_key(finding: Finding) -> tuple[str, str]:
    """(component, version) as every aggregate key spells them: trimmed, lowercased, v-prefix dropped."""
    return normalize_component(finding.component), normalize_version(finding.version)


def is_error_result(result: Any) -> bool:
    """Only failure paths set ``error``, so an empty message still marks a failure."""
    return isinstance(result, dict) and "error" in result


def _adopt_smallest_spelling(existing: Finding, finding: Finding, id_prefix: str) -> None:
    """Keep the smallest raw (component, version) spelling so arrival order cannot pick the finding id."""
    existing.component, existing.version = min(
        (existing.component, existing.version),
        (finding.component, finding.version),
        key=lambda cv: (cv[0], cv[1] or ""),
    )
    existing.id = f"{id_prefix}{existing.component}:{existing.version}"


def _record_license(enrichment: DependencyEnrichment, entry: dict[str, Any]) -> None:
    """Record a license once per (spdx_id, source): every SBOM of a scan feeds the same enrichment."""
    if not any(e["spdx_id"] == entry["spdx_id"] and e["source"] == entry["source"] for e in enrichment.licenses):
        enrichment.licenses.append(entry)


def _deps_dev_block(metadata: dict[str, Any]) -> dict[str, Any]:
    """The persisted deps_dev block, copied key by key so cached metadata cannot add stray fields."""
    project = metadata.get("project") or {}
    dependents = metadata.get("dependents") or {}
    scorecard = metadata.get("scorecard") or {}
    block: dict[str, Any] = {"project_url": project["url"]} if project.get("url") else {}
    block |= {key: project[key] for key in ("stars", "forks", "open_issues") if project.get(key) is not None}
    if dependents.get("total") is not None:
        block["dependents"] = {key: dependents.get(key) for key in ("total", "direct", "indirect")}
    if scorecard.get("overall_score") is not None:
        block["scorecard"] = {key: scorecard.get(key) for key in ("overall_score", "date", "checks_count")}
    # homepage and repository persist as the flat enrichment fields.
    links = {key: url for key, url in (metadata.get("links") or {}).items() if key not in ("homepage", "repository")}
    if links:
        block["links"] = links
    if metadata.get("published_at"):
        block["published_at"] = metadata["published_at"]
    if metadata.get("is_deprecated"):
        block["is_deprecated"] = True
    if metadata.get("known_advisories"):
        block["known_advisories"] = metadata["known_advisories"]
    block |= {flag: True for flag in ("has_attestations", "has_slsa_provenance") if metadata.get(flag)}
    return block


class ResultAggregator:
    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}
        self._dependency_enrichments: dict[str, DependencyEnrichment] = {}

    def _get_or_create_enrichment(self, name: str, version: str, purl: str | None = None) -> DependencyEnrichment:
        """Get or create a DependencyEnrichment, keyed by canonical purl so qualifier variants merge and same-named packages from different ecosystems stay apart."""
        key = canonical_purl(purl) if purl else f"{name}@{version}"
        if key not in self._dependency_enrichments:
            self._dependency_enrichments[key] = DependencyEnrichment(
                name=name, version=version, purl=key if purl else None
            )
        return self._dependency_enrichments[key]

    @staticmethod
    def _plausible_spdx_token(token: str) -> bool:
        if token.upper() in _LICENSE_SENTINELS:
            return False
        if token.startswith("LicenseRef-"):
            return True
        return all(_SPDX_TOKEN_SHAPE.match(part) for part in token.split(" WITH "))

    @staticmethod
    def _sanitize_deps_dev_license(lic: Any) -> str | None:
        """deps.dev emits sentinels like 'non-standard'; drop those but keep any plausible SPDX id or expression."""
        if not isinstance(lic, str):
            return None
        value = lic.strip()
        if not value or value.upper() in _LICENSE_SENTINELS:
            return None
        normalized = normalize_spdx_id(value)
        if normalized in LICENSE_DATABASE:
            return normalized
        tokens = tokenize_license_string(value)
        if tokens and all(ResultAggregator._plausible_spdx_token(t) for t in tokens):
            return value
        return None

    @staticmethod
    def _record_deps_dev_license(enrichment: DependencyEnrichment, lic: Any, source: str) -> None:
        spdx_id = ResultAggregator._sanitize_deps_dev_license(lic)
        if spdx_id:
            _record_license(enrichment, {"spdx_id": spdx_id, "source": source})
            enrichment.primary_license = enrichment.primary_license or spdx_id

    def enrich_from_deps_dev(self, name: str, version: str, metadata: dict[str, Any]) -> None:
        """Enrich dependency with data from deps.dev; the version's own license beats the repository's."""
        enrichment = self._get_or_create_enrichment(name, version, metadata.get("purl"))
        if "deps_dev" not in enrichment.sources:
            enrichment.sources.append("deps_dev")

        project = metadata.get("project") or {}
        links = metadata.get("links") or {}
        for lic in metadata.get("licenses") or []:
            self._record_deps_dev_license(enrichment, lic, "deps_dev")
        self._record_deps_dev_license(enrichment, project.get("license"), "deps_dev_project")

        # The version-level links homepage is more specific than the project one.
        enrichment.homepage = enrichment.homepage or links.get("homepage") or project.get("homepage")
        enrichment.repository_url = project.get("url") or enrichment.repository_url or links.get("repository")
        if project.get("description"):
            enrichment.description = project["description"]

        block = _deps_dev_block(metadata)
        new_links = block.pop("links", {})
        enrichment.deps_dev.update(block)
        if new_links:
            enrichment.deps_dev.setdefault("links", {}).update(new_links)

    @staticmethod
    def _scanner_license_takes_primary(enrichment: DependencyEnrichment, category: str | None) -> bool:
        """Most-restrictive-wins keeps multi-license primaries order-independent; a scanner classification always beats a deps.dev guess (no category)."""
        if enrichment.primary_license is None or enrichment.license_category is None:
            return True
        incoming_rank = CATEGORY_RESTRICTIVENESS.get(category or "", 0)
        current_rank = CATEGORY_RESTRICTIVENESS.get(enrichment.license_category, 0)
        return incoming_rank > current_rank

    def enrich_from_license_scanner(self, name: str, version: str, license_info: dict[str, Any]) -> None:
        """Enrich dependency with one classified license from the license compliance scanner."""
        spdx_id = license_info.get("license")
        if not spdx_id:
            return

        enrichment = self._get_or_create_enrichment(name, version, license_info.get("purl"))
        if "license_compliance" not in enrichment.sources:
            enrichment.sources.append("license_compliance")

        category = license_info.get("category")
        if self._scanner_license_takes_primary(enrichment, category):
            enrichment.primary_license = spdx_id
            enrichment.license_category = category
        if license_info.get("spdx_expression"):
            enrichment.license_expression = license_info["spdx_expression"]

        _record_license(
            enrichment,
            {
                "spdx_id": spdx_id,
                "source": "license_compliance",
                "category": category,
                "explanation": license_info.get("explanation"),
            },
        )

        for risk in license_info.get("risks") or []:
            if risk not in enrichment.license_risks:
                enrichment.license_risks.append(risk)
        for obligation in license_info.get("obligations") or []:
            if obligation not in enrichment.license_obligations:
                enrichment.license_obligations.append(obligation)

    def aggregate(self, analyzer_name: str, result: dict[str, Any], source: str | None = None) -> None:
        """
        Dispatches the result to the specific normalizer based on analyzer name.
        """
        if not result:
            return

        if is_error_result(result):
            error_details = result.get("details", result.get("output"))
            self.add_scan_error(analyzer_name, str(result["error"]), error_details=error_details, source=source)
            return

        if normalize := _NORMALIZERS.get(analyzer_name):
            normalize(self, result, source=source)

    def add_scan_error(
        self,
        analyzer_name: str,
        message: str,
        *,
        partial: bool = False,
        error_details: Any = None,
        source: str | None = None,
    ) -> None:
        """Record an analyzer failure; every distinct failure stays listed in the description."""
        outcome = "returned partial results" if partial else "failed"
        error = {"source": source, "message": f"Scanner '{analyzer_name}' {outcome}: {message}"}
        if error_details is not None:
            error["error_details"] = error_details
        finding_id = f"SCAN-ERROR-{analyzer_name}"
        existing = self.findings.get(finding_id)
        if existing is None:
            self.findings[finding_id] = Finding(
                id=finding_id,
                type=FindingType.SYSTEM_WARNING,
                severity=Severity.HIGH,
                component="Scanner System",
                version="",
                description=error["message"],
                scanners=[analyzer_name],
                details=SystemWarningDetails(error_details=error_details, errors=[error]).model_dump(exclude_none=True),
                found_in=[source] if source else [],
            )
            return
        errors = existing.details["errors"]
        if error not in errors:
            errors.append(error)
        existing.description = "; ".join(sorted({e["message"] for e in errors}))
        if source and source not in existing.found_in:
            existing.found_in.append(source)

    @staticmethod
    def _merge_cluster(cluster: list[Finding], representative: str) -> Finding:
        """Merge one package's findings into the entry carrying the most qualified name."""
        if len(cluster) == 1:
            return cluster[0]
        primary = next(f for f in cluster if normalize_component(f.component) == representative)
        # Merge in name order so the outcome does not depend on analyzer completion order.
        for other in sorted(cluster, key=lambda f: normalize_component(f.component)):
            if other is primary:
                continue
            merge_findings_data(primary, other)
        return primary

    def _reduce_vuln_group(self, group: list[Finding]) -> list[Finding]:
        """Split a vuln group into one primary per distinct package."""
        if len(group) == 1:
            return [group[0]]

        representatives = cluster_by_package_identity(f.component for f in group)
        clusters: dict[str, list[Finding]] = {}
        for f in group:
            key = representatives[normalize_component(f.component)]
            clusters.setdefault(key, []).append(f)

        return [self._merge_cluster(cluster, key) for key, cluster in clusters.items()]

    @staticmethod
    def _finding_sort_key(f: Finding) -> tuple[str, str, str, str]:
        return (str(f.type), normalize_component(f.component), f.version or "", f.id)

    def get_findings(self) -> list[Finding]:
        """Return deduplicated findings with merge/link post-processing applied.

        Analyzers aggregate in completion order, so every step here is kept order-independent:
        identical scanner output must yield an identical finding set between runs.
        """
        final_findings: list[Finding] = []
        vuln_groups: dict[tuple[str, str], list[Finding]] = {}
        for f in self.findings.values():
            if f.type == FindingType.VULNERABILITY:
                component, version = _package_key(f)
                vuln_groups.setdefault((extract_artifact_name(component), version), []).append(f)
            elif f.type == FindingType.SAST:
                final_findings.append(to_sast_aggregate(f))
            else:
                final_findings.append(f)

        merged_ids: set = set()
        for group in vuln_groups.values():
            for p in self._reduce_vuln_group(group):
                if p.id not in merged_ids:
                    final_findings.append(p)
                    merged_ids.add(p.id)

        final_findings.sort(key=self._finding_sort_key)
        for f in final_findings:
            entries = f.details.get("vulnerabilities")
            if entries:
                dedupe_vulnerability_entries(entries)
                entries.sort(key=lambda entry: str(entry.get("id")))
                f.details["fixed_version"] = aggregate_fixed_version(entries, f.version)

        self._link_related_findings_by_component(final_findings)

        for f in final_findings:
            f.match = compute_match_signature(f)

        return final_findings

    @staticmethod
    def _link_finding_group(component_findings: list[Finding], link_same_type: bool) -> None:
        for i, f1 in enumerate(component_findings):
            for f2 in component_findings[i + 1 :]:
                if f1.id != f2.id and (link_same_type or f1.type != f2.type):
                    cross_link_pair(f1, f2)

    def _link_related_findings_by_component(self, findings: list[Finding]) -> None:
        """Link findings for the same package, or the same file path, to each other.

        ``related_findings_omitted`` counts the siblings left unlinked: same-type hits in one file,
        which exchange no context but grow quadratically, and every sibling past
        ``MAX_CROSS_LINK_GROUP_SIZE``. No severity, count or score depends on the links.
        """
        representatives = cluster_by_package_identity(
            f.component for f in findings if f.component and f.type in PACKAGE_FINDING_TYPES
        )
        component_map: dict[tuple[str, str], list[Finding]] = {}

        for f in findings:
            if not f.component:
                continue
            if f.type in PACKAGE_FINDING_TYPES:
                key = ("package", representatives[normalize_component(f.component)])
            else:
                key = ("file", f.component.strip())
            component_map.setdefault(key, []).append(f)

        for (kind, _), component_findings in component_map.items():
            if len(component_findings) <= 1:
                continue
            record_additional_types(component_findings)
            if len(component_findings) > MAX_CROSS_LINK_GROUP_SIZE:
                for finding in component_findings:
                    finding.related_findings_omitted = len(component_findings) - 1
                continue
            self._link_finding_group(component_findings, link_same_type=kind == "package")
            if kind == "file":
                type_counts = Counter(f.type for f in component_findings)
                for finding in component_findings:
                    finding.related_findings_omitted = type_counts[finding.type] - 1 or None

    def get_dependency_enrichments(self) -> list[dict[str, Any]]:
        """Enrichment entries for persistence: canonical purl (the match key), name/version (purl-less match), payload."""
        return [
            {
                "name": enrichment.name,
                "version": enrichment.version,
                "purl": enrichment.purl,
                "data": enrichment.to_mongo_dict(),
            }
            for enrichment in self._dependency_enrichments.values()
        ]

    def add_finding(self, finding: Finding, source: str | None = None) -> None:
        """Add a finding, merging if one already exists for the same key."""
        if finding.type == FindingType.VULNERABILITY:
            self._add_vulnerability_finding(finding, source)
        elif finding.type == FindingType.QUALITY:
            self._add_quality_finding(finding, source)
        else:
            self._add_generic_finding(finding, source)

    @staticmethod
    def _build_vuln_entry(finding: Finding) -> VulnerabilityEntry:
        """Build a vulnerability entry dict from a finding."""
        refs_from_details = finding.details.get("references", []) or []

        entry: VulnerabilityEntry = {
            "id": finding.id,
            "severity": finding.severity,
            "description": finding.description,
            "fixed_version": (
                str(finding.details.get("fixed_version")) if finding.details.get("fixed_version") else None
            ),
            "cvss_score": (float(cvss) if (cvss := finding.details.get("cvss_score")) is not None else None),
            "cvss_vector": (str(finding.details.get("cvss_vector")) if finding.details.get("cvss_vector") else None),
            "references": sorted(set(refs_from_details)),
            "aliases": finding.aliases,
            "scanners": finding.scanners,
            "details": {k: v for k, v in finding.details.items() if k not in _ENTRY_LEVEL_KEYS},
        }
        ecosystem_specific = finding.details.get("ecosystem_specific")
        if ecosystem_specific:
            # get_symbols_for_finding reads it at the entry level for symbol reachability.
            entry["ecosystem_specific"] = ecosystem_specific
        return entry

    def _merge_vuln_into_existing(
        self, existing: Finding, finding: Finding, vuln_entry: VulnerabilityEntry, source: str | None
    ) -> None:
        """Merge a vulnerability finding into an existing aggregate."""
        absorb_header(existing, finding, source)
        _adopt_smallest_spelling(existing, finding, "")
        existing.details["vulnerabilities"].append(vuln_entry)
        existing.description = ""

    def _add_vulnerability_finding(self, finding: Finding, source: str | None = None) -> None:
        comp_key, version_key = _package_key(finding)
        agg_key = f"{AGG_KEY_VULNERABILITY}:{comp_key}:{version_key}"

        vuln_entry = self._build_vuln_entry(finding)

        if agg_key in self.findings:
            self._merge_vuln_into_existing(self.findings[agg_key], finding, vuln_entry, source)
        else:
            agg_details: VulnerabilityAggregatedDetails = {"vulnerabilities": [vuln_entry]}

            self.findings[agg_key] = Finding(
                id=f"{finding.component}:{finding.version}",
                type=FindingType.VULNERABILITY,
                severity=finding.severity,
                component=finding.component,
                version=finding.version,
                description="",
                scanners=finding.scanners,
                details=agg_details,
                found_in=[source] if source else [],
            )

    @staticmethod
    def _quality_issue_type(finding: Finding) -> str:
        """Only the scorecard and maintainer_risk normalizers emit QUALITY findings."""
        return "scorecard" if finding.id.startswith(f"{FindingIdPrefix.SCORECARD}-") else "maintainer_risk"

    @staticmethod
    def _has_maintenance_issue(finding: Finding, issue_type: str) -> bool:
        """Detect whether the finding carries a maintenance signal."""
        if issue_type == "scorecard":
            return "Maintained" in finding.details.get("critical_issues", [])
        return any(r.get("type") in MAINTENANCE_RISK_TYPES for r in finding.details.get("risks", []))

    def _merge_quality_into_existing(
        self,
        existing: Finding,
        finding: Finding,
        quality_entry: QualityEntry,
        issue_type: str,
        has_maintenance: bool,
        source: str | None,
    ) -> None:
        """Merge a quality finding into an existing aggregated finding."""
        absorb_header(existing, finding, source)
        _adopt_smallest_spelling(existing, finding, "QUALITY:")
        quality_list: list[QualityEntry] = existing.details.get("quality_issues", [])
        existing_ids = {q.get("id") for q in quality_list}
        if finding.id not in existing_ids:
            quality_list.append(quality_entry)
            existing.details["quality_issues"] = quality_list
            existing.details["issue_count"] = len(quality_list)

        if issue_type == "scorecard" and finding.details.get("overall_score") is not None:
            existing.details["overall_score"] = finding.details.get("overall_score")

        if has_maintenance:
            existing.details["has_maintenance_issues"] = True

        update_quality_description(existing)

    def _add_quality_finding(self, finding: Finding, source: str | None = None) -> None:
        """Aggregate quality findings (scorecard, maintainer_risk, ...) by component+version."""
        comp_key, version_key = _package_key(finding)
        agg_key = f"{AGG_KEY_QUALITY}:{comp_key}:{version_key}"

        issue_type = self._quality_issue_type(finding)
        has_maintenance = self._has_maintenance_issue(finding, issue_type)

        quality_entry: QualityEntry = {
            "id": finding.id,
            "type": issue_type,
            "severity": finding.severity,
            "description": finding.description,
            "scanners": finding.scanners,
            "details": finding.details,
        }

        if agg_key in self.findings:
            self._merge_quality_into_existing(
                self.findings[agg_key], finding, quality_entry, issue_type, has_maintenance, source
            )
            return

        agg_details: QualityAggregatedDetails = {
            "quality_issues": [quality_entry],
            "overall_score": (finding.details.get("overall_score") if issue_type == "scorecard" else None),
            "has_maintenance_issues": has_maintenance,
            "issue_count": 1,
        }
        self.findings[agg_key] = Finding(
            id=f"QUALITY:{finding.component}:{finding.version}",
            type=FindingType.QUALITY,
            severity=finding.severity,
            component=finding.component,
            version=finding.version,
            description=finding.description,
            scanners=finding.scanners,
            details=agg_details,
            found_in=[source] if source else [],
        )

    @staticmethod
    def _merge_generic_into_existing(existing: Finding, finding: Finding) -> None:
        """Merge order-free: the side whose scanners sort first owns description and conflicting detail keys."""
        incoming_owns = min(finding.scanners, default="") < min(existing.scanners, default="")
        absorb_header(existing, finding)
        if incoming_owns:
            existing.details = {**existing.details, **finding.details}
            existing.description = finding.description
        else:
            existing.details = {**finding.details, **existing.details}
        existing.aliases = sorted(set(existing.aliases) | set(finding.aliases))

    def _add_generic_finding(self, finding: Finding, source: str | None = None) -> None:
        """Add a finding keyed by ``type:id:component:version``, merging on an exact match of that key."""
        if source and source not in finding.found_in:
            finding.found_in.append(source)

        comp_key, version_key = _package_key(finding)
        key = f"{finding.type}:{finding.id}:{comp_key}:{version_key}"
        if existing := self.findings.get(key):
            self._merge_generic_into_existing(existing, finding)
        else:
            self.findings[key] = finding
