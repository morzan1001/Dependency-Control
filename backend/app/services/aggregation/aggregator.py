"""ResultAggregator - aggregates findings from multiple analyzers."""

import re
from typing import Any

from app.core.constants import (
    AGG_KEY_QUALITY,
    AGG_KEY_VULNERABILITY,
    UNKNOWN_LICENSE_PATTERNS,
    get_severity_value,
)
from app.models.finding import Finding, FindingType, Severity
from app.schemas.enrichment import DependencyEnrichment
from app.schemas.finding import (
    QualityAggregatedDetails,
    QualityEntry,
    VulnerabilityAggregatedDetails,
    VulnerabilityEntry,
)
from app.schemas.finding_details import SystemWarningDetails
from app.services.aggregation.components import (
    cluster_by_package_identity,
    extract_artifact_name,
    normalize_component,
)
from app.services.aggregation.cross_link import cross_link_pair
from app.services.aggregation.merging import (
    merge_findings_data,
    merge_sast_findings,
    merge_vulnerability_into_list,
)
from app.services.aggregation.quality import update_quality_description
from app.services.aggregation.scorecard import enrich_with_scorecard
from app.services.aggregation.versions import (
    normalize_version,
    resolve_fixed_versions,
)
from app.services.analyzers.license_compliance.constants import (
    CATEGORY_RESTRICTIVENESS,
    LICENSE_DATABASE,
)
from app.services.analyzers.license_compliance.normalizer import (
    normalize_license as normalize_spdx_id,
)
from app.services.analyzers.license_compliance.normalizer import (
    tokenize_license_string,
)
from app.services.analyzers.purl_utils import canonical_purl
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

_LICENSE_SENTINELS = UNKNOWN_LICENSE_PATTERNS | {"NON-STANDARD"}
_SPDX_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_SPDX_WITH_SPLIT = re.compile(r"\s+WITH\s+")
_CATEGORY_RANK_BY_VALUE = {category.value: rank for category, rank in CATEGORY_RESTRICTIVENESS.items()}


class ResultAggregator:
    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}
        self.alias_map: dict[str, str] = {}
        self._scorecard_cache: dict[str, dict[str, Any]] = {}
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
        return all(_SPDX_TOKEN_SHAPE.match(part) for part in _SPDX_WITH_SPLIT.split(token))

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
    def _apply_deps_dev_project(enrichment: DependencyEnrichment, project: dict[str, Any]) -> None:
        """Apply deps.dev project block to enrichment."""
        if not project:
            return
        enrichment.project_url = project.get("url")
        enrichment.stars = project.get("stars")
        enrichment.forks = project.get("forks")
        enrichment.open_issues = project.get("open_issues")
        if project.get("description"):
            enrichment.description = project.get("description")
        if project.get("url"):
            enrichment.repository_url = project.get("url")
        project_license = ResultAggregator._sanitize_deps_dev_license(project.get("license"))
        if project_license and not enrichment.primary_license:
            enrichment.primary_license = project_license
            enrichment.licenses.append({"spdx_id": project_license, "source": "deps_dev_project"})

    @staticmethod
    def _apply_deps_dev_links(enrichment: DependencyEnrichment, links: dict[str, Any]) -> None:
        """Apply deps.dev links block to enrichment."""
        if not links:
            return
        if links.get("homepage") and not enrichment.homepage:
            enrichment.homepage = links.get("homepage")
        if links.get("repository") and not enrichment.repository_url:
            enrichment.repository_url = links.get("repository")
        if links.get("documentation"):
            enrichment.documentation_url = links.get("documentation")
        if links.get("issues"):
            enrichment.issues_url = links.get("issues")
        if links.get("changelog"):
            enrichment.changelog_url = links.get("changelog")
        known_keys = {"homepage", "repository", "documentation", "issues", "changelog"}
        for key, url in links.items():
            if key not in known_keys:
                enrichment.additional_links[key] = url

    @staticmethod
    def _apply_deps_dev_flags(enrichment: DependencyEnrichment, metadata: dict[str, Any]) -> None:
        """Apply deps.dev top-level flag fields to enrichment."""
        if metadata.get("published_at"):
            enrichment.published_at = metadata.get("published_at")
        if metadata.get("is_deprecated"):
            enrichment.is_deprecated = True
        if metadata.get("known_advisories"):
            enrichment.known_advisories = metadata.get("known_advisories", [])
        if metadata.get("has_attestations"):
            enrichment.has_attestations = True
        if metadata.get("has_slsa_provenance"):
            enrichment.has_slsa_provenance = True

    @staticmethod
    def _apply_deps_dev_licenses(enrichment: DependencyEnrichment, licenses: list[Any]) -> None:
        """Apply deps.dev license list to enrichment."""
        for lic in licenses:
            spdx_id = ResultAggregator._sanitize_deps_dev_license(lic)
            if spdx_id:
                enrichment.licenses.append({"spdx_id": spdx_id, "source": "deps_dev"})
                if not enrichment.primary_license:
                    enrichment.primary_license = spdx_id

    def enrich_from_deps_dev(self, name: str, version: str, metadata: dict[str, Any]) -> None:
        """Enrich dependency with data from deps.dev."""
        enrichment = self._get_or_create_enrichment(name, version, metadata.get("purl"))
        if "deps_dev" not in enrichment.sources:
            enrichment.sources.append("deps_dev")

        self._apply_deps_dev_project(enrichment, metadata.get("project", {}))

        dependents = metadata.get("dependents", {})
        if dependents:
            enrichment.dependents_total = dependents.get("total")
            enrichment.dependents_direct = dependents.get("direct")
            enrichment.dependents_indirect = dependents.get("indirect")

        scorecard = metadata.get("scorecard", {})
        if scorecard:
            enrichment.scorecard_score = scorecard.get("overall_score")
            enrichment.scorecard_date = scorecard.get("date")
            enrichment.scorecard_checks_count = scorecard.get("checks_count")

        self._apply_deps_dev_links(enrichment, metadata.get("links", {}))
        self._apply_deps_dev_flags(enrichment, metadata)
        self._apply_deps_dev_licenses(enrichment, metadata.get("licenses", []))

        # The version-level links homepage is more specific than the project one.
        project_homepage = (metadata.get("project") or {}).get("homepage")
        if project_homepage and not enrichment.homepage:
            enrichment.homepage = project_homepage

    def record_scorecard(self, component_key: str, data: dict[str, Any]) -> None:
        """Cache OpenSSF Scorecard data (keyed by ``name@version``) applied to findings during finalization."""
        self._scorecard_cache[component_key] = data

    @staticmethod
    def _scanner_license_takes_primary(enrichment: DependencyEnrichment, category: str | None) -> bool:
        """Most-restrictive-wins keeps multi-license primaries order-independent; a scanner classification always beats a deps.dev guess (no category)."""
        if enrichment.primary_license is None or enrichment.license_category is None:
            return True
        incoming_rank = _CATEGORY_RANK_BY_VALUE.get(category or "", 0)
        current_rank = _CATEGORY_RANK_BY_VALUE.get(enrichment.license_category, 0)
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

        already_recorded = any(
            entry.get("spdx_id") == spdx_id and entry.get("source") == "license_compliance"
            for entry in enrichment.licenses
        )
        if not already_recorded:
            enrichment.licenses.append(
                {
                    "spdx_id": spdx_id,
                    "source": "license_compliance",
                    "category": category,
                    "explanation": license_info.get("explanation"),
                }
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

        if "error" in result:
            self.add_finding(
                Finding(
                    id=f"SCAN-ERROR-{analyzer_name}",
                    type=FindingType.SYSTEM_WARNING,
                    severity=Severity.HIGH,
                    component="Scanner System",
                    version="",
                    description=f"Scanner '{analyzer_name}' failed: {result.get('error')}",
                    scanners=[analyzer_name],
                    details=SystemWarningDetails(
                        error_details=result.get("details", result.get("output", "No details provided"))
                    ).model_dump(exclude_none=True),
                ),
                source=source,
            )
            return

        normalizers = {
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

        if analyzer_name in normalizers:
            normalizers[analyzer_name](self, result, source=source)

    @staticmethod
    def _sast_group_key(f: Finding) -> tuple:
        """Build the SAST grouping key for a finding."""
        line = f.details.get("line")
        start_line = f.details.get("start", {}).get("line")
        effective_line = line or start_line or 0
        rule_id = f.details.get("rule_id", "unknown")
        return (f.component, effective_line, rule_id)

    @staticmethod
    def _vuln_group_key(f: Finding) -> tuple | None:
        """Build vulnerability grouping key, or None if finding has no vulns."""
        vulns = {v["id"] for v in f.details.get("vulnerabilities", [])}
        if not vulns:
            return None
        component = f.component.lower() if f.component else "unknown"
        version = f.version or "unknown"
        return (extract_artifact_name(component), version)

    def _partition_findings(
        self, current_findings: list[Finding]
    ) -> tuple[dict[tuple, list[Finding]], dict[Any, list[Finding]]]:
        """Partition findings into SAST and vulnerability groups."""
        groups: dict[tuple, list[Finding]] = {}
        sast_groups: dict[Any, list[Finding]] = {}

        for f in current_findings:
            if f.type == FindingType.SAST:
                sast_groups.setdefault(self._sast_group_key(f), []).append(f)
                continue
            if f.type != FindingType.VULNERABILITY:
                continue
            group_key = self._vuln_group_key(f)
            if group_key is None:
                continue
            groups.setdefault(group_key, []).append(f)

        return groups, sast_groups

    @staticmethod
    def _merge_cluster(cluster: list[Finding], representative: str) -> Finding:
        """Merge one package's findings into the entry carrying the most qualified name."""
        if len(cluster) == 1:
            return cluster[0]
        primary = next(f for f in cluster if normalize_component(f.component or "") == representative)
        # Merge in name order so the outcome does not depend on analyzer completion order.
        for other in sorted(cluster, key=lambda f: normalize_component(f.component or "")):
            if other is primary:
                continue
            merge_findings_data(primary, other)
        return primary

    def _reduce_vuln_group(self, group: list[Finding]) -> list[Finding]:
        """Split a vuln group into one primary per distinct package."""
        if len(group) == 1:
            return [group[0]]

        representatives = cluster_by_package_identity(f.component or "" for f in group)
        clusters: dict[str, list[Finding]] = {}
        for f in group:
            key = representatives[normalize_component(f.component or "")]
            clusters.setdefault(key, []).append(f)

        return [self._merge_cluster(cluster, key) for key, cluster in clusters.items()]

    @staticmethod
    def _finding_sort_key(f: Finding) -> tuple[str, str, str, str]:
        return (str(f.type), normalize_component(f.component or ""), f.version or "", f.id)

    def get_findings(self) -> list[Finding]:
        """Return deduplicated findings with merge/link post-processing applied.

        Analyzers aggregate in completion order, so every step here is kept order-independent:
        identical scanner output must yield an identical finding set between runs.
        """
        current_findings = list(self.findings.values())
        groups, sast_groups = self._partition_findings(current_findings)

        final_findings: list[Finding] = [
            f for f in current_findings if f.type not in (FindingType.VULNERABILITY, FindingType.SAST)
        ]

        for group in sast_groups.values():
            if not group:
                continue
            # Single-item groups still pass through so every SAST finding gets a consistent sast_findings list.
            merged_f = merge_sast_findings(sorted(group, key=self._finding_sort_key))
            if merged_f:
                final_findings.append(merged_f)

        merged_ids: set = set()
        for group in groups.values():
            for p in self._reduce_vuln_group(group):
                if p.id not in merged_ids:
                    final_findings.append(p)
                    merged_ids.add(p.id)

        final_findings.sort(key=self._finding_sort_key)
        for f in final_findings:
            entries = f.details.get("vulnerabilities") if isinstance(f.details, dict) else None
            if entries:
                entries.sort(key=lambda entry: str(entry.get("id")))

        self._link_related_findings_by_component(final_findings)
        enrich_with_scorecard(final_findings, self._scorecard_cache)

        from app.services.waivers.signature import compute_match_signature

        for f in final_findings:
            f.match = compute_match_signature(f)

        return final_findings

    def _link_finding_group(self, component_findings: list[Finding]) -> None:
        for i, f1 in enumerate(component_findings):
            for f2 in component_findings[i + 1 :]:
                if f1.id == f2.id:
                    continue
                cross_link_pair(f1, f2)

    def _link_related_findings_by_component(self, findings: list[Finding]) -> None:
        """Link all findings for the same package to each other (vuln, outdated, quality, license, eol)."""
        representatives = cluster_by_package_identity(f.component for f in findings if f.component)
        component_map: dict[str, list[Finding]] = {}

        for f in findings:
            if not f.component:
                continue
            key = representatives[normalize_component(f.component)]
            component_map.setdefault(key, []).append(f)

        for component_findings in component_map.values():
            if len(component_findings) > 1:
                self._link_finding_group(component_findings)

    def get_dependency_enrichments(self) -> list[dict[str, Any]]:
        """Enrichment entries for persistence: canonical purl (cross-scan key), name/version (per-scan match), payload."""
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

    def _build_vuln_entry(self, finding: Finding, source: str | None) -> VulnerabilityEntry:
        """Build a vulnerability entry dict from a finding."""
        refs_from_details = finding.details.get("references", []) or []

        entry: VulnerabilityEntry = {
            "id": finding.id,
            "severity": finding.severity,
            "description": finding.description,
            "description_source": (finding.scanners[0] if finding.scanners else "unknown"),
            "fixed_version": (
                str(finding.details.get("fixed_version")) if finding.details.get("fixed_version") else None
            ),
            "cvss_score": (float(cvss) if (cvss := finding.details.get("cvss_score")) is not None else None),
            "cvss_vector": (str(finding.details.get("cvss_vector")) if finding.details.get("cvss_vector") else None),
            "references": sorted(set(refs_from_details)),
            "aliases": finding.aliases or [],
            "scanners": finding.scanners or [],
            "source": source,
            # ecosystem_specific is lifted to the entry level below, not duplicated here.
            "details": {k: v for k, v in (finding.details or {}).items() if k != "ecosystem_specific"},
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
        existing.scanners = sorted(set(existing.scanners + finding.scanners))

        if get_severity_value(finding.severity) > get_severity_value(existing.severity):
            existing.severity = finding.severity

        vuln_list: list[VulnerabilityEntry] = existing.details.get("vulnerabilities", [])
        merge_vulnerability_into_list(vuln_list, vuln_entry)
        existing.details["vulnerabilities"] = vuln_list
        existing.description = ""

        if source and source not in existing.found_in:
            existing.found_in.append(source)

        fvs = [str(v.get("fixed_version")) for v in vuln_list if v.get("fixed_version")]
        existing.details["fixed_version"] = resolve_fixed_versions(fvs) if fvs else None

    def _add_vulnerability_finding(self, finding: Finding, source: str | None = None) -> None:
        comp_key = normalize_component(finding.component or "unknown")
        version_key = normalize_version(finding.version or "unknown")
        agg_key = f"{AGG_KEY_VULNERABILITY}:{comp_key}:{version_key}"

        vuln_entry = self._build_vuln_entry(finding, source)

        if agg_key in self.findings:
            self._merge_vuln_into_existing(self.findings[agg_key], finding, vuln_entry, source)
        else:
            agg_details: VulnerabilityAggregatedDetails = {
                "vulnerabilities": [vuln_entry],
                "fixed_version": (
                    str(finding.details.get("fixed_version")) if finding.details.get("fixed_version") else None
                ),
            }

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
        """Determine the quality issue-type bucket for a finding id."""
        if finding.id.startswith("SCORECARD-"):
            return "scorecard"
        if finding.id.startswith("MAINT-"):
            return "maintainer_risk"
        return "other"

    @staticmethod
    def _has_maintenance_issue(finding: Finding, issue_type: str) -> bool:
        """Detect whether the finding carries a maintenance signal."""
        if issue_type == "scorecard":
            return "Maintained" in finding.details.get("critical_issues", [])
        if issue_type == "maintainer_risk":
            maintenance_risk_types = ("stale_package", "infrequent_updates", "archived_repo")
            risks = finding.details.get("risks", [])
            return any(r.get("type", "") in maintenance_risk_types for r in risks)
        return False

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
        existing.scanners = sorted(set(existing.scanners + finding.scanners))

        if get_severity_value(finding.severity) > get_severity_value(existing.severity):
            existing.severity = finding.severity

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

        if source and source not in existing.found_in:
            existing.found_in.append(source)

        update_quality_description(existing)

    def _add_quality_finding(self, finding: Finding, source: str | None = None) -> None:
        """Aggregate quality findings (scorecard, maintainer_risk, ...) by component+version."""
        raw_comp = finding.component if finding.component else "unknown"
        comp_key = normalize_component(raw_comp)
        raw_version = finding.version if finding.version else "unknown"
        version_key = normalize_version(raw_version)
        agg_key = f"{AGG_KEY_QUALITY}:{comp_key}:{version_key}"

        issue_type = self._quality_issue_type(finding)
        has_maintenance = self._has_maintenance_issue(finding, issue_type)

        quality_entry: QualityEntry = {
            "id": finding.id,
            "type": issue_type,
            "severity": finding.severity,
            "description": finding.description,
            "scanners": finding.scanners or [],
            "source": source,
            "details": finding.details or {},
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
            "scanners": finding.scanners or [],
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

    def _lookup_existing_key(self, finding: Finding, comp_key: str, lookup_key_id: str) -> str | None:
        """Resolve an existing aggregate key for the finding via id or aliases."""
        if lookup_key_id in self.alias_map:
            return self.alias_map[lookup_key_id]
        for alias in finding.aliases:
            lookup_key_alias = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
            if lookup_key_alias in self.alias_map:
                return self.alias_map[lookup_key_alias]
        return None

    @staticmethod
    def _merge_generic_into_existing(existing: Finding, finding: Finding, source: str | None) -> None:
        """Merge a generic finding's fields into an existing aggregate."""
        existing.scanners = sorted(set(existing.scanners + finding.scanners))

        if get_severity_value(finding.severity) > get_severity_value(existing.severity):
            existing.severity = finding.severity

        existing.details.update(finding.details)

        new_aliases = set(existing.aliases)
        new_aliases.update(finding.aliases)
        if finding.id != existing.id:
            new_aliases.add(finding.id)
        existing.aliases = sorted(new_aliases)

        if source and source not in existing.found_in:
            existing.found_in.append(source)

    def _record_alias_map(self, finding: Finding, comp_key: str, lookup_key_id: str, target_key: str) -> None:
        """Record id and alias lookups for a finding pointing to target_key."""
        self.alias_map[lookup_key_id] = target_key
        for alias in finding.aliases:
            k = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
            self.alias_map[k] = target_key

    def _add_generic_finding(self, finding: Finding, source: str | None = None) -> None:
        """Add a finding keyed by ``type:id:component:version``, merging on ID or alias match."""
        if source and source not in finding.found_in:
            finding.found_in.append(source)

        comp_key = finding.component.lower() if finding.component else "unknown"
        primary_key = f"{finding.type}:{finding.id}:{comp_key}:{finding.version}"
        lookup_key_id = f"{finding.type}:{comp_key}:{finding.version}:{finding.id}"

        existing_key = self._lookup_existing_key(finding, comp_key, lookup_key_id)

        if existing_key and existing_key in self.findings:
            self._merge_generic_into_existing(self.findings[existing_key], finding, source)
            self._record_alias_map(finding, comp_key, lookup_key_id, existing_key)
            return

        self.findings[primary_key] = finding
        self._record_alias_map(finding, comp_key, lookup_key_id, primary_key)
