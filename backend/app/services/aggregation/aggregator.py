"""ResultAggregator - aggregates findings from multiple analyzers."""

from typing import Any, Dict, List, Optional

from app.core.constants import (
    AGG_KEY_QUALITY,
    AGG_KEY_VULNERABILITY,
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
from app.services.aggregation.components import (
    extract_artifact_name,
    normalize_component,
)
from app.services.aggregation.cross_link import (
    add_context_to_vulnerability,
    cross_link_pair,
)
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
from app.services.normalizers.crypto import normalize_crypto
from app.services.normalizers.iac import normalize_kics
from app.services.normalizers.lifecycle import normalize_eol, normalize_outdated
from app.services.normalizers.license import normalize_license
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


class ResultAggregator:
    def __init__(self) -> None:
        self.findings: Dict[str, Finding] = {}
        self.alias_map: Dict[str, str] = {}
        self._scorecard_cache: Dict[str, Dict[str, Any]] = {}
        self._dependency_enrichments: Dict[str, DependencyEnrichment] = {}
        self._license_data: Dict[str, Dict[str, Any]] = {}

    def _get_or_create_enrichment(self, name: str, version: str) -> DependencyEnrichment:
        """Get or create a DependencyEnrichment for the given package."""
        key = f"{name}@{version}"
        if key not in self._dependency_enrichments:
            self._dependency_enrichments[key] = DependencyEnrichment(name=name, version=version)
        return self._dependency_enrichments[key]

    @staticmethod
    def _apply_deps_dev_project(enrichment: DependencyEnrichment, project: Dict[str, Any]) -> None:
        """Apply deps.dev project block to enrichment."""
        if not project:
            return
        enrichment.stars = project.get("stars")
        enrichment.forks = project.get("forks")
        enrichment.open_issues = project.get("open_issues")
        if project.get("description"):
            enrichment.description = project.get("description")
        if project.get("url"):
            enrichment.repository_url = project.get("url")
        if project.get("license") and not enrichment.primary_license:
            enrichment.primary_license = project.get("license")
            enrichment.licenses.append({"spdx_id": project.get("license"), "source": "deps_dev_project"})

    @staticmethod
    def _apply_deps_dev_links(enrichment: DependencyEnrichment, links: Dict[str, Any]) -> None:
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
    def _apply_deps_dev_flags(enrichment: DependencyEnrichment, metadata: Dict[str, Any]) -> None:
        """Apply deps.dev top-level flag fields to enrichment."""
        if metadata.get("published_at"):
            enrichment.published_at = metadata.get("published_at")
        if metadata.get("is_deprecated"):
            enrichment.is_deprecated = True
        if metadata.get("is_default"):
            enrichment.is_default_version = True
        if metadata.get("known_advisories"):
            enrichment.known_advisories = metadata.get("known_advisories", [])
        if metadata.get("has_attestations"):
            enrichment.has_attestations = True
        if metadata.get("has_slsa_provenance"):
            enrichment.has_slsa_provenance = True

    @staticmethod
    def _apply_deps_dev_licenses(enrichment: DependencyEnrichment, licenses: List[Any]) -> None:
        """Apply deps.dev license list to enrichment."""
        for lic in licenses:
            if isinstance(lic, str):
                enrichment.licenses.append({"spdx_id": lic, "source": "deps_dev"})
                if not enrichment.primary_license:
                    enrichment.primary_license = lic

    def enrich_from_deps_dev(self, name: str, version: str, metadata: Dict[str, Any]) -> None:
        """Enrich dependency with data from deps.dev."""
        enrichment = self._get_or_create_enrichment(name, version)
        if "deps_dev" not in enrichment.sources:
            enrichment.sources.append("deps_dev")

        self._apply_deps_dev_project(enrichment, metadata.get("project", {}))

        dependents = metadata.get("dependents", {})
        if dependents:
            enrichment.dependents_total = dependents.get("total")
            enrichment.dependents_direct = dependents.get("direct")

        scorecard = metadata.get("scorecard", {})
        if scorecard:
            enrichment.scorecard_score = scorecard.get("overall_score")
            enrichment.scorecard_date = scorecard.get("date")
            enrichment.scorecard_checks_count = scorecard.get("checks_count")

        self._apply_deps_dev_links(enrichment, metadata.get("links", {}))
        self._apply_deps_dev_flags(enrichment, metadata)
        self._apply_deps_dev_licenses(enrichment, metadata.get("licenses", []))

    def record_scorecard(self, component_key: str, data: Dict[str, Any]) -> None:
        """Record OpenSSF Scorecard data for a component, keyed by ``name@version``.

        Caches scorecard details that are later applied to findings via
        ``enrich_with_scorecard`` during finalization.
        """
        self._scorecard_cache[component_key] = data

    def enrich_from_license_scanner(self, name: str, version: str, license_info: Dict[str, Any]) -> None:
        """Enrich dependency with data from license compliance scanner."""
        enrichment = self._get_or_create_enrichment(name, version)
        if "license_compliance" not in enrichment.sources:
            enrichment.sources.append("license_compliance")

        spdx_id = license_info.get("license")
        if spdx_id:
            # License scanner provides detailed analysis - use as primary
            enrichment.primary_license = spdx_id
            enrichment.license_category = license_info.get("category")
            enrichment.licenses.append(
                {
                    "spdx_id": spdx_id,
                    "source": "license_compliance",
                    "category": license_info.get("category"),
                    "explanation": license_info.get("explanation"),
                }
            )

            if license_info.get("risks"):
                enrichment.license_risks.extend(license_info.get("risks", []))
            if license_info.get("obligations"):
                enrichment.license_obligations.extend(license_info.get("obligations", []))

            self._license_data[f"{name}@{version}"] = license_info

    def aggregate(self, analyzer_name: str, result: Dict[str, Any], source: Optional[str] = None) -> None:
        """
        Dispatches the result to the specific normalizer based on analyzer name.
        """
        if not result:
            return

        # Check for scanner errors
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
                    details={"error_details": result.get("details", result.get("output", "No details provided"))},
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
    def _vuln_group_key(f: Finding) -> Optional[tuple]:
        """Build vulnerability grouping key, or None if finding has no vulns."""
        vulns = {v["id"] for v in f.details.get("vulnerabilities", [])}
        if not vulns:
            return None
        component = f.component.lower() if f.component else "unknown"
        version = f.version or "unknown"
        return (extract_artifact_name(component), version)

    def _partition_findings(
        self, current_findings: List[Finding]
    ) -> tuple[Dict[tuple, List[Finding]], Dict[Any, List[Finding]]]:
        """Partition findings into SAST and vulnerability groups."""
        groups: Dict[tuple, List[Finding]] = {}
        sast_groups: Dict[Any, List[Finding]] = {}

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
    def _merge_cluster(cluster: List[Finding]) -> Finding:
        """Merge a single component cluster into one primary finding."""
        if len(cluster) == 1:
            return cluster[0]
        # Prefer the shortest name as primary (usually the clean one).
        primary = min(cluster, key=lambda x: len(x.component))
        for other in cluster:
            if other is primary:
                continue
            merge_findings_data(primary, other)
        return primary

    @staticmethod
    def _cross_link_primaries(primaries: List[Finding]) -> None:
        """Cross-link a list of cluster primaries by id."""
        if len(primaries) <= 1:
            return
        for i, p1 in enumerate(primaries):
            for p2 in primaries[i + 1 :]:
                cross_link_pair(p1, p2)

    def _reduce_vuln_group(self, group: List[Finding]) -> List[Finding]:
        """Cluster findings in a vuln group by artifact and return primaries."""
        if len(group) == 1:
            return [group[0]]

        component_clusters: Dict[str, List] = {}
        for f in group:
            name = extract_artifact_name(f.component or "")
            component_clusters.setdefault(name, []).append(f)

        cluster_primaries = [self._merge_cluster(c) for c in component_clusters.values()]
        self._cross_link_primaries(cluster_primaries)
        return cluster_primaries

    def get_findings(self) -> List[Finding]:
        """Return deduplicated findings with merge/link post-processing applied."""
        current_findings = list(self.findings.values())
        groups, sast_groups = self._partition_findings(current_findings)

        final_findings: List[Finding] = [
            f for f in current_findings if f.type not in (FindingType.VULNERABILITY, FindingType.SAST)
        ]

        for group in sast_groups.values():
            if not group:
                continue
            # Single-item groups still go through merge_sast_findings to ensure
            # a consistent sast_findings list structure on all SAST findings.
            merged_f = merge_sast_findings(group)
            if merged_f:
                final_findings.append(merged_f)

        merged_ids: set = set()
        for group in groups.values():
            for p in self._reduce_vuln_group(group):
                if p.id not in merged_ids:
                    final_findings.append(p)
                    merged_ids.add(p.id)

        self._link_related_findings_by_component(final_findings)
        enrich_with_scorecard(final_findings, self._scorecard_cache)

        from app.services.waivers.signature import compute_match_signature

        for f in final_findings:
            f.match = compute_match_signature(f)

        return final_findings

    def _link_finding_group(self, component_findings: List[Finding]) -> None:
        for i, f1 in enumerate(component_findings):
            for f2 in component_findings[i + 1 :]:
                if f1.id == f2.id:
                    continue
                cross_link_pair(f1, f2)
                add_context_to_vulnerability(f1, f2)
                add_context_to_vulnerability(f2, f1)

    def _link_related_findings_by_component(self, findings: List[Finding]) -> None:
        """Link all findings for the same component to each other (vuln, outdated, quality, license, eol)."""
        component_map: Dict[str, List[Finding]] = {}

        for f in findings:
            if not f.component:
                continue
            key = extract_artifact_name(f.component)
            if key not in component_map:
                component_map[key] = []
            component_map[key].append(f)

        for component_findings in component_map.values():
            if len(component_findings) > 1:
                self._link_finding_group(component_findings)

    def get_dependency_enrichments(self) -> Dict[str, Dict[str, Any]]:
        """Return enrichment data keyed by ``package_name@version`` for MongoDB updates."""
        result = {}
        for key, enrichment in self._dependency_enrichments.items():
            result[key] = enrichment.to_mongo_dict()
        return result

    def get_license_data(self) -> Dict[str, Dict[str, Any]]:
        """Return detailed license analysis data per package."""
        return self._license_data

    def add_finding(self, finding: Finding, source: Optional[str] = None) -> None:
        """Add a finding, merging if one already exists for the same key."""
        if finding.type == FindingType.VULNERABILITY:
            self._add_vulnerability_finding(finding, source)
        elif finding.type == FindingType.QUALITY:
            self._add_quality_finding(finding, source)
        else:
            self._add_generic_finding(finding, source)

    def _build_vuln_entry(self, finding: Finding, source: Optional[str]) -> VulnerabilityEntry:
        """Build a vulnerability entry dict from a finding."""
        refs_from_details = finding.details.get("references", []) or []
        urls_from_details = finding.details.get("urls", []) or []
        combined_refs = list(set(refs_from_details) | set(urls_from_details))

        return {
            "id": finding.id,
            "severity": finding.severity,
            "description": finding.description,
            "description_source": (finding.scanners[0] if finding.scanners else "unknown"),
            "fixed_version": (
                str(finding.details.get("fixed_version")) if finding.details.get("fixed_version") else None
            ),
            "cvss_score": (float(cvss) if (cvss := finding.details.get("cvss_score")) is not None else None),
            "cvss_vector": (str(finding.details.get("cvss_vector")) if finding.details.get("cvss_vector") else None),
            "references": combined_refs,
            "aliases": finding.aliases or [],
            "scanners": finding.scanners or [],
            "source": source,
            "details": {k: v for k, v in (finding.details or {}).items() if k != "urls"},
        }

    def _merge_vuln_into_existing(
        self, existing: Finding, finding: Finding, vuln_entry: VulnerabilityEntry, source: Optional[str]
    ) -> None:
        """Merge a vulnerability finding into an existing aggregate."""
        existing.scanners = list(set(existing.scanners + finding.scanners))

        if get_severity_value(finding.severity) > get_severity_value(existing.severity):
            existing.severity = finding.severity

        vuln_list: List[VulnerabilityEntry] = existing.details.get("vulnerabilities", [])
        merge_vulnerability_into_list(vuln_list, vuln_entry)
        existing.details["vulnerabilities"] = vuln_list
        existing.description = ""

        if source and source not in existing.found_in:
            existing.found_in.append(source)

        fvs = [str(v.get("fixed_version")) for v in vuln_list if v.get("fixed_version")]
        existing.details["fixed_version"] = resolve_fixed_versions(fvs) if fvs else None

    def _add_vulnerability_finding(self, finding: Finding, source: Optional[str] = None) -> None:
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
        source: Optional[str],
    ) -> None:
        """Merge a quality finding into an existing aggregated finding."""
        existing.scanners = list(set(existing.scanners + finding.scanners))

        if get_severity_value(finding.severity) > get_severity_value(existing.severity):
            existing.severity = finding.severity

        quality_list: List[QualityEntry] = existing.details.get("quality_issues", [])
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

    def _add_quality_finding(self, finding: Finding, source: Optional[str] = None) -> None:
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

    def _lookup_existing_key(self, finding: Finding, comp_key: str, lookup_key_id: str) -> Optional[str]:
        """Resolve an existing aggregate key for the finding via id or aliases."""
        if lookup_key_id in self.alias_map:
            return self.alias_map[lookup_key_id]
        for alias in finding.aliases:
            lookup_key_alias = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
            if lookup_key_alias in self.alias_map:
                return self.alias_map[lookup_key_alias]
        return None

    @staticmethod
    def _merge_generic_into_existing(existing: Finding, finding: Finding, source: Optional[str]) -> None:
        """Merge a generic finding's fields into an existing aggregate."""
        existing.scanners = list(set(existing.scanners + finding.scanners))

        if get_severity_value(finding.severity) > get_severity_value(existing.severity):
            existing.severity = finding.severity

        existing.details.update(finding.details)

        new_aliases = set(existing.aliases)
        new_aliases.update(finding.aliases)
        if finding.id != existing.id:
            new_aliases.add(finding.id)
        existing.aliases = list(new_aliases)

        if source and source not in existing.found_in:
            existing.found_in.append(source)

    def _record_alias_map(self, finding: Finding, comp_key: str, lookup_key_id: str, target_key: str) -> None:
        """Record id and alias lookups for a finding pointing to target_key."""
        self.alias_map[lookup_key_id] = target_key
        for alias in finding.aliases:
            k = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
            self.alias_map[k] = target_key

    def _add_generic_finding(self, finding: Finding, source: Optional[str] = None) -> None:
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
