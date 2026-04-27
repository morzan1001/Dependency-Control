"""ResultAggregator - aggregates findings from multiple analyzers.

The pure helpers used here live in sibling modules:
  * versions.py    - parse/normalize/aggregate version strings
  * components.py  - normalize component names, extract artifact ids
  * cross_link.py  - link related findings + add contextual info
  * merging.py     - SAST + vulnerability merge primitives
  * quality.py     - quality finding description summary
  * scorecard.py   - enrich findings with scorecard data

Methods on the class itself either mutate ``self.findings`` /
``self._dependency_enrichments`` / ``self._scorecard_cache`` /
``self._license_data`` or are part of the public API. The thin private
wrappers (e.g. ``_parse_version_key``) exist only because some tests still
call them by name on an instance; they delegate to the helper modules.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

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
    calculate_aggregated_fixed_version,
    normalize_version,
    parse_version_key,
    resolve_fixed_versions,
)
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
        self._scorecard_cache: Dict[str, Dict[str, Any]] = {}  # component@version -> scorecard data
        self._dependency_enrichments: Dict[str, DependencyEnrichment] = {}  # name@version -> enrichment
        self._license_data: Dict[str, Dict[str, Any]] = {}  # name@version -> license analysis from scanner

    def _get_or_create_enrichment(self, name: str, version: str) -> DependencyEnrichment:
        """Get or create a DependencyEnrichment for the given package."""
        key = f"{name}@{version}"
        if key not in self._dependency_enrichments:
            self._dependency_enrichments[key] = DependencyEnrichment(name=name, version=version)
        return self._dependency_enrichments[key]

    def enrich_from_deps_dev(self, name: str, version: str, metadata: Dict[str, Any]) -> None:
        """Enrich dependency with data from deps.dev."""
        enrichment = self._get_or_create_enrichment(name, version)
        if "deps_dev" not in enrichment.sources:
            enrichment.sources.append("deps_dev")

        # Project info (stars, forks, etc.)
        project = metadata.get("project", {})
        if project:
            enrichment.stars = project.get("stars")
            enrichment.forks = project.get("forks")
            enrichment.open_issues = project.get("open_issues")
            if project.get("description"):
                enrichment.description = project.get("description")
            if project.get("url"):
                enrichment.repository_url = project.get("url")
            # Add license from project if we don't have one yet
            if project.get("license") and not enrichment.primary_license:
                enrichment.primary_license = project.get("license")
                enrichment.licenses.append({"spdx_id": project.get("license"), "source": "deps_dev_project"})

        # Dependents
        dependents = metadata.get("dependents", {})
        if dependents:
            enrichment.dependents_total = dependents.get("total")
            enrichment.dependents_direct = dependents.get("direct")

        # Scorecard
        scorecard = metadata.get("scorecard", {})
        if scorecard:
            enrichment.scorecard_score = scorecard.get("overall_score")
            enrichment.scorecard_date = scorecard.get("date")
            enrichment.scorecard_checks_count = scorecard.get("checks_count")

        # Links from deps.dev
        links = metadata.get("links", {})
        if links:
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
            # Store other links
            for key, url in links.items():
                if key not in [
                    "homepage",
                    "repository",
                    "documentation",
                    "issues",
                    "changelog",
                ]:
                    enrichment.additional_links[key] = url

        # Publication info
        if metadata.get("published_at"):
            enrichment.published_at = metadata.get("published_at")
        if metadata.get("is_deprecated"):
            enrichment.is_deprecated = True
        if metadata.get("is_default"):
            enrichment.is_default_version = True

        # Licenses from deps.dev version endpoint
        licenses = metadata.get("licenses", [])
        for lic in licenses:
            if isinstance(lic, str):
                enrichment.licenses.append({"spdx_id": lic, "source": "deps_dev"})
                if not enrichment.primary_license:
                    enrichment.primary_license = lic

        # Security info
        if metadata.get("known_advisories"):
            enrichment.known_advisories = metadata.get("known_advisories", [])
        if metadata.get("has_attestations"):
            enrichment.has_attestations = True
        if metadata.get("has_slsa_provenance"):
            enrichment.has_slsa_provenance = True

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

            # Add risks and obligations
            if license_info.get("risks"):
                enrichment.license_risks.extend(license_info.get("risks", []))
            if license_info.get("obligations"):
                enrichment.license_obligations.extend(license_info.get("obligations", []))

            # Store full license data for reference
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
                    severity=Severity.HIGH,  # High visibility
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
        }

        if analyzer_name in normalizers:
            normalizers[analyzer_name](self, result, source=source)

    def get_findings(self) -> List[Finding]:
        """
        Returns the list of deduplicated findings with post-processing for merging and linking related findings.
        """
        # 1. Start with current findings
        current_findings = list(self.findings.values())

        # 2. Group by Version + CVE-Set hash to find potential duplicates
        # Map: (version, cve_set_hash) -> List[Finding]
        groups: Dict[tuple, List[Finding]] = {}
        sast_groups: Dict[Any, List[Finding]] = {}  # Map: (component, line) -> List[Finding]

        for f in current_findings:
            if f.type == FindingType.SAST:
                # Group SAST findings by component (file), line number, AND rule_id
                # This prevents merging distinct issues (e.g. different secrets) that happen to be on the same line.
                line = f.details.get("line")
                start_line = f.details.get("start", {}).get("line")
                effective_line = line or start_line or 0
                rule_id = f.details.get("rule_id", "unknown")

                # Normalize component path to avoid slight mismatches (e.g. ./file vs file)
                # But component should be normalized by ingest already.
                sast_key = (f.component, effective_line, rule_id)

                if sast_key not in sast_groups:
                    sast_groups[sast_key] = []
                sast_groups[sast_key].append(f)
                continue

            if f.type != FindingType.VULNERABILITY:
                continue

            vulns = {v["id"] for v in f.details.get("vulnerabilities", [])}
            if not vulns:
                continue

            # Group by artifact-name+version (not full qualified name!)
            # This ensures cross-format names like "org.postgresql:postgresql"
            # and "postgresql" land in the same group for proper merging.
            component = f.component.lower() if f.component else "unknown"
            version = f.version or "unknown"
            artifact = extract_artifact_name(component)
            group_key = (artifact, version)

            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(f)

        # 3. Process groups
        final_findings = []
        merged_ids = set()

        # Add non-vulnerability/non-sast findings first
        for f in current_findings:
            if f.type != FindingType.VULNERABILITY and f.type != FindingType.SAST:
                final_findings.append(f)

        # Process SAST groups
        for key, group in sast_groups.items():
            if not group:
                continue

            # Single item groups are also normalized via merge_sast_findings
            # to ensure consistent structure (sast_findings list) for all SAST findings
            merged_f = merge_sast_findings(group)
            if merged_f:
                final_findings.append(merged_f)

        # Process vulnerability groups
        for key, group in groups.items():
            # If group has only 1 item, no merge needed
            if len(group) == 1:
                if group[0].id not in merged_ids:
                    final_findings.append(group[0])
                    merged_ids.add(group[0].id)
                continue

            # Group findings by normalized artifact name (O(n) instead of O(n²))
            component_clusters: Dict[str, List] = {}
            for f in group:
                name = extract_artifact_name(f.component or "")
                if name not in component_clusters:
                    component_clusters[name] = []
                component_clusters[name].append(f)

            clusters = list(component_clusters.values())

            # Now process clusters
            cluster_primaries = []

            for cluster in clusters:
                if len(cluster) == 1:
                    f = cluster[0]
                    cluster_primaries.append(f)
                else:
                    # Merge cluster into one finding
                    # Prefer the shortest name as primary (usually the "clean" one)
                    primary = min(cluster, key=lambda x: len(x.component))

                    # Merge others into primary
                    for other in cluster:
                        if other == primary:
                            continue
                        merge_findings_data(primary, other)

                    cluster_primaries.append(primary)

            # Link remaining clusters as "Related Findings"
            if len(cluster_primaries) > 1:
                for i in range(len(cluster_primaries)):
                    p1 = cluster_primaries[i]
                    for j in range(i + 1, len(cluster_primaries)):
                        p2 = cluster_primaries[j]

                        if p2.id not in p1.related_findings:
                            p1.related_findings.append(p2.id)
                        if p1.id not in p2.related_findings:
                            p2.related_findings.append(p1.id)

            # Add to final results
            for p in cluster_primaries:
                if p.id not in merged_ids:
                    final_findings.append(p)
                    merged_ids.add(p.id)

        # Link all findings for the same component together (without merging)
        # Each finding type remains separate, only linked via related_findings
        self._link_related_findings_by_component(final_findings)

        # Enrich findings with scorecard data
        enrich_with_scorecard(final_findings, self._scorecard_cache)

        return final_findings

    # ------------------------------------------------------------------
    # Thin wrappers around pure helpers (kept for tests that reference
    # the underscore-prefixed methods on ResultAggregator instances).
    # ------------------------------------------------------------------
    @staticmethod
    def _cross_link_pair(f1: Finding, f2: Finding) -> None:
        """Add cross-references between two findings."""
        cross_link_pair(f1, f2)

    def _link_finding_group(self, component_findings: List[Finding]) -> None:
        """Link all findings in a component group to each other and add context."""
        for i, f1 in enumerate(component_findings):
            for f2 in component_findings[i + 1 :]:
                if f1.id == f2.id:
                    continue
                cross_link_pair(f1, f2)
                add_context_to_vulnerability(f1, f2)
                add_context_to_vulnerability(f2, f1)

    def _link_related_findings_by_component(self, findings: List[Finding]) -> None:
        """
        Links ALL findings for the same component together, regardless of type.
        This creates a web of related findings where:
        - Vulnerability <-> Outdated <-> Quality <-> License <-> EOL

        Also adds contextual info from other finding types to vulnerability findings.
        """
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

    def _add_context_to_vulnerability(self, vuln_finding: Finding, other_finding: Finding) -> None:
        """Adds contextual information from other finding types to a vulnerability finding."""
        add_context_to_vulnerability(vuln_finding, other_finding)

    def get_dependency_enrichments(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns aggregated dependency enrichment data from all sources.
        Key format: "package_name@version"

        This merges data from:
        - deps.dev (stars, forks, scorecard, links, etc.)
        - license_compliance scanner (detailed license analysis)

        Returns a dict suitable for updating dependencies in MongoDB.
        """
        result = {}
        for key, enrichment in self._dependency_enrichments.items():
            result[key] = enrichment.to_mongo_dict()
        return result

    def get_license_data(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns detailed license analysis data per package.
        Useful for license compliance reporting.
        """
        return self._license_data

    def _enrich_with_scorecard(self, findings: List[Finding]) -> None:
        """Enriches non-scorecard findings with scorecard data for the same component."""
        enrich_with_scorecard(findings, self._scorecard_cache)

    # ------------------------------------------------------------------
    # Version helpers - delegate to versions.py
    # ------------------------------------------------------------------
    def _parse_version_key(self, v: str) -> Tuple[Tuple[int, Union[int, str]], ...]:
        return parse_version_key(v)

    def _calculate_aggregated_fixed_version(self, fixed_versions_list: List[str]) -> Optional[str]:
        return calculate_aggregated_fixed_version(fixed_versions_list)

    def _resolve_fixed_versions(self, versions: List[str]) -> Optional[str]:
        return resolve_fixed_versions(versions)

    def _normalize_version(self, version: str) -> str:
        return normalize_version(version)

    # ------------------------------------------------------------------
    # Component helpers - delegate to components.py
    # ------------------------------------------------------------------
    def _normalize_component(self, component: str) -> str:
        return normalize_component(component)

    def _extract_artifact_name(self, component: str) -> str:
        return extract_artifact_name(component)

    # ------------------------------------------------------------------
    # Merge helpers - delegate to merging.py
    # ------------------------------------------------------------------
    def _merge_sast_findings(self, findings: List[Finding]) -> Optional[Finding]:
        return merge_sast_findings(findings)

    def _merge_vulnerability_into_list(self, target_list: List[Any], source_entry: VulnerabilityEntry) -> None:
        merge_vulnerability_into_list(target_list, source_entry)

    def _merge_findings_data(self, target: Finding, source: Finding) -> None:
        merge_findings_data(target, source)

    def add_finding(self, finding: Finding, source: Optional[str] = None) -> None:
        """
        Adds a finding to the map, merging if it already exists.
        """
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
        # Update scanners
        existing.scanners = list(set(existing.scanners + finding.scanners))

        # Update severity (max of all vulns)
        if get_severity_value(finding.severity) > get_severity_value(existing.severity):
            existing.severity = finding.severity

        # Merge into vulnerabilities list
        vuln_list: List[VulnerabilityEntry] = existing.details.get("vulnerabilities", [])
        merge_vulnerability_into_list(vuln_list, vuln_entry)
        existing.details["vulnerabilities"] = vuln_list
        existing.description = ""

        # Update found_in
        if source and source not in existing.found_in:
            existing.found_in.append(source)

        # Update top-level fixed_version
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

    def _add_quality_finding(self, finding: Finding, source: Optional[str] = None) -> None:
        """
        Adds a quality finding to the map, aggregating multiple quality issues
        (scorecard, maintainer_risk, etc.) for the same component+version.
        Structure mirrors vulnerability aggregation with a quality_issues list.
        """
        # Normalize keys
        raw_comp = finding.component if finding.component else "unknown"
        comp_key = normalize_component(raw_comp)

        # Normalize version
        raw_version = finding.version if finding.version else "unknown"
        version_key = normalize_version(raw_version)

        # Primary key for the AGGREGATED quality finding
        agg_key = f"{AGG_KEY_QUALITY}:{comp_key}:{version_key}"

        # Determine quality issue type based on finding ID
        if finding.id.startswith("SCORECARD-"):
            issue_type = "scorecard"
        elif finding.id.startswith("MAINT-"):
            issue_type = "maintainer_risk"
        else:
            issue_type = "other"

        # Create the quality entry (similar to VulnerabilityEntry)
        quality_entry: QualityEntry = {
            "id": finding.id,
            "type": issue_type,
            "severity": finding.severity,
            "description": finding.description,
            "scanners": finding.scanners or [],
            "source": source,
            "details": finding.details or {},
        }

        # Check for maintenance issues
        has_maintenance = False
        if issue_type == "scorecard":
            critical = finding.details.get("critical_issues", [])
            if "Maintained" in critical:
                has_maintenance = True
        elif issue_type == "maintainer_risk":
            risks = finding.details.get("risks", [])
            for risk in risks:
                risk_type = risk.get("type", "")
                if risk_type in (
                    "stale_package",
                    "infrequent_updates",
                    "archived_repo",
                ):
                    has_maintenance = True
                    break

        if agg_key in self.findings:
            existing = self.findings[agg_key]

            # 1. Update Scanners of the aggregate
            existing.scanners = list(set(existing.scanners + finding.scanners))

            # 2. Update Severity of the aggregate (Max of all sources)
            existing_severity_val = get_severity_value(existing.severity)
            new_severity_val = get_severity_value(finding.severity)
            if new_severity_val > existing_severity_val:
                existing.severity = finding.severity

            # 3. Add to quality_issues list (check for duplicates by ID)
            quality_list: List[QualityEntry] = existing.details.get("quality_issues", [])
            existing_ids = {q.get("id") for q in quality_list}

            if finding.id not in existing_ids:
                quality_list.append(quality_entry)
                existing.details["quality_issues"] = quality_list
                existing.details["issue_count"] = len(quality_list)

            # 4. Update overall_score if this is a scorecard finding
            if issue_type == "scorecard" and finding.details.get("overall_score") is not None:
                existing.details["overall_score"] = finding.details.get("overall_score")

            # 5. Update maintenance flag
            if has_maintenance:
                existing.details["has_maintenance_issues"] = True

            # Update found_in
            if source and source not in existing.found_in:
                existing.found_in.append(source)

            # Update description to reflect issue count
            update_quality_description(existing)

        else:
            # Create new Aggregate Quality Finding
            agg_details: QualityAggregatedDetails = {
                "quality_issues": [quality_entry],
                "overall_score": (finding.details.get("overall_score") if issue_type == "scorecard" else None),
                "has_maintenance_issues": has_maintenance,
                "issue_count": 1,
                "scanners": finding.scanners or [],
            }

            agg_finding = Finding(
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
            self.findings[agg_key] = agg_finding

    def _update_quality_description(self, finding: Finding) -> None:
        """Updates the description of an aggregated quality finding."""
        update_quality_description(finding)

    def _add_generic_finding(self, finding: Finding, source: Optional[str] = None) -> None:
        """
        Adds a finding to the map, merging if it already exists.
        Key for deduplication: type + id + component + version
        """
        # Add source to finding
        if source:
            if source not in finding.found_in:
                finding.found_in.append(source)

        # Construct a unique key for the finding itself (as if it were new)
        comp_key = finding.component.lower() if finding.component else "unknown"
        primary_key = f"{finding.type}:{finding.id}:{comp_key}:{finding.version}"

        # Check if we already have a record for this finding via ID or Aliases
        existing_key = None

        # 1. Check exact ID match (fast path)
        lookup_key_id = f"{finding.type}:{comp_key}:{finding.version}:{finding.id}"
        if lookup_key_id in self.alias_map:
            existing_key = self.alias_map[lookup_key_id]

        # 2. If not found, check aliases
        if not existing_key:
            for alias in finding.aliases:
                lookup_key_alias = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
                if lookup_key_alias in self.alias_map:
                    existing_key = self.alias_map[lookup_key_alias]
                    break

        if existing_key and existing_key in self.findings:
            existing = self.findings[existing_key]

            # 1. Merge scanners list
            existing.scanners = list(set(existing.scanners + finding.scanners))

            # 2. Merge Severity (keep highest)
            existing_severity_val = get_severity_value(existing.severity)
            new_severity_val = get_severity_value(finding.severity)

            if new_severity_val > existing_severity_val:
                existing.severity = finding.severity

            # 3. Merge Details
            existing.details.update(finding.details)

            # 4. Merge Aliases (if any)
            new_aliases = set(existing.aliases)
            new_aliases.update(finding.aliases)
            # If the IDs are different, add the other ID as alias
            if finding.id != existing.id:
                new_aliases.add(finding.id)
            existing.aliases = list(new_aliases)

            # 5. Merge found_in
            if source:
                if source not in existing.found_in:
                    existing.found_in.append(source)

            # Update alias_map with new aliases pointing to existing_key
            self.alias_map[lookup_key_id] = existing_key
            for alias in finding.aliases:
                k = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
                self.alias_map[k] = existing_key

        else:
            self.findings[primary_key] = finding

            # Populate alias_map
            self.alias_map[lookup_key_id] = primary_key
            for alias in finding.aliases:
                k = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
                self.alias_map[k] = primary_key
