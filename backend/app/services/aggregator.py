import hashlib
import re
from typing import Any, Dict, List

from app.models.finding import Finding, FindingType, Severity
from app.schemas.finding import (
    SecretDetails,
    VulnerabilityAggregatedDetails,
    VulnerabilityEntry,
    QualityAggregatedDetails,
    QualityEntry,
)
from app.schemas.enrichment import DependencyEnrichment

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}


class ResultAggregator:
    def __init__(self):
        self.findings: Dict[str, Finding] = {}
        self.alias_map: Dict[str, str] = {}
        self._scorecard_cache: Dict[str, Dict[str, Any]] = (
            {}
        )  # component@version -> scorecard data
        self._dependency_enrichments: Dict[str, DependencyEnrichment] = (
            {}
        )  # name@version -> enrichment
        self._license_data: Dict[str, Dict[str, Any]] = (
            {}
        )  # name@version -> license analysis from scanner

    def _get_or_create_enrichment(
        self, name: str, version: str
    ) -> DependencyEnrichment:
        """Get or create a DependencyEnrichment for the given package."""
        key = f"{name}@{version}"
        if key not in self._dependency_enrichments:
            self._dependency_enrichments[key] = DependencyEnrichment(
                name=name, version=version
            )
        return self._dependency_enrichments[key]

    def _enrich_from_deps_dev(self, name: str, version: str, metadata: Dict[str, Any]):
        """Enrich dependency with data from deps.dev."""
        enrichment = self._get_or_create_enrichment(name, version)
        enrichment.sources.add("deps_dev")

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
                enrichment.licenses.append(
                    {"spdx_id": project.get("license"), "source": "deps_dev_project"}
                )

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

    def _enrich_from_license_scanner(
        self, name: str, version: str, license_info: Dict[str, Any]
    ):
        """Enrich dependency with data from license compliance scanner."""
        enrichment = self._get_or_create_enrichment(name, version)
        enrichment.sources.add("license_compliance")

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
                enrichment.license_obligations.extend(
                    license_info.get("obligations", [])
                )

            # Store full license data for reference
            self._license_data[f"{name}@{version}"] = license_info

    def aggregate(self, analyzer_name: str, result: Dict[str, Any], source: str = None):
        """
        Dispatches the result to the specific normalizer based on analyzer name.
        """
        if not result:
            return

        # Check for scanner errors
        if "error" in result:
            self._add_finding(
                Finding(
                    id=f"SCAN-ERROR-{analyzer_name}",
                    type=FindingType.SYSTEM_WARNING,
                    severity=Severity.HIGH,  # High visibility
                    component="Scanner System",
                    version="",
                    description=f"Scanner '{analyzer_name}' failed: {result.get('error')}",
                    scanners=[analyzer_name],
                    details={
                        "error_details": result.get(
                            "details", result.get("output", "No details provided")
                        )
                    },
                ),
                source=source,
            )
            return

        normalizers = {
            "trivy": self._normalize_trivy,
            "grype": self._normalize_grype,
            "osv": self._normalize_osv,
            "outdated_packages": self._normalize_outdated,
            "license_compliance": self._normalize_license,
            "deps_dev": self._normalize_scorecard,
            "os_malware": self._normalize_malware,
            "end_of_life": self._normalize_eol,
            "typosquatting": self._normalize_typosquatting,
            "trufflehog": self._normalize_trufflehog,
            "opengrep": self._normalize_opengrep,
            "kics": self._normalize_kics,
            "bearer": self._normalize_bearer,
            "hash_verification": self._normalize_hash_verification,
            "maintainer_risk": self._normalize_maintainer_risk,
        }

        if analyzer_name in normalizers:
            normalizers[analyzer_name](result, source=source)

    def get_findings(self) -> List[Finding]:
        """
        Returns the list of deduplicated findings with post-processing for merging and linking related findings.
        """
        # 1. Start with current findings
        current_findings = list(self.findings.values())

        # 2. Group by Version + CVE-Set hash to find potential duplicates
        # Map: (version, cve_set_hash) -> List[Finding]
        groups = {}

        for f in current_findings:
            if f.type != FindingType.VULNERABILITY:
                continue

            vulns = set(v["id"] for v in f.details.get("vulnerabilities", []))
            if not vulns:
                continue

            # Create a deterministic key for the set of vulnerabilities
            # vuln_key = frozenset(vulns)

            # Group by version only. We will rely on component name matching to merge.
            # This allows merging findings for the same component that have DIFFERENT sets of vulnerabilities
            # (e.g. different scanners found different things).
            key = f.version
            if key not in groups:
                groups[key] = []
            groups[key].append(f)

        # 3. Process groups
        final_findings = []
        merged_ids = set()

        # Add non-vulnerability findings first
        for f in current_findings:
            if f.type != FindingType.VULNERABILITY:
                final_findings.append(f)

        # Process vulnerability groups
        for key, group in groups.items():
            # If group has only 1 item, no merge needed
            if len(group) == 1:
                if group[0].id not in merged_ids:
                    final_findings.append(group[0])
                    merged_ids.add(group[0].id)
                continue

            # Try to merge items within the group based on name similarity
            clusters = []
            processed_in_group = set()

            for i in range(len(group)):
                if i in processed_in_group:
                    continue

                f1 = group[i]
                cluster = [f1]
                processed_in_group.add(i)

                for j in range(i + 1, len(group)):
                    if j in processed_in_group:
                        continue
                    f2 = group[j]

                    if self._is_same_component_name(f1.component, f2.component):
                        cluster.append(f2)
                        processed_in_group.add(j)

                clusters.append(cluster)

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
                        self._merge_findings_data(primary, other)

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

        # Link all findings for the same component together
        self._link_related_findings_by_component(final_findings)

        # Enrich findings with scorecard data
        self._enrich_with_scorecard(final_findings)

        return final_findings

    def _link_related_findings_by_component(self, findings: List[Finding]):
        """
        Links ALL findings for the same component together, regardless of type.
        This creates a web of related findings where:
        - Vulnerability ↔ Outdated ↔ Quality ↔ License ↔ EOL
        
        Also adds contextual info from other finding types to vulnerability findings.
        """
        # Build a map of all findings by component (normalized lowercase)
        # Key: component_lower -> List[Finding]
        component_map: Dict[str, List[Finding]] = {}
        
        for f in findings:
            if not f.component:
                continue
            key = f.component.lower()
            if key not in component_map:
                component_map[key] = []
            component_map[key].append(f)

        # Process each component group
        for component_key, component_findings in component_map.items():
            if len(component_findings) <= 1:
                continue  # Nothing to link
            
            # Link all findings in this component group to each other
            for i, f1 in enumerate(component_findings):
                for f2 in component_findings[i + 1:]:
                    # Skip if same finding
                    if f1.id == f2.id:
                        continue
                    
                    # Add cross-references
                    if f2.id not in f1.related_findings:
                        f1.related_findings.append(f2.id)
                    if f1.id not in f2.related_findings:
                        f2.related_findings.append(f1.id)
                    
                    # Add contextual info to vulnerability findings
                    self._add_context_to_vulnerability(f1, f2)
                    self._add_context_to_vulnerability(f2, f1)

    def _add_context_to_vulnerability(self, vuln_finding: Finding, other_finding: Finding):
        """
        Adds contextual information from other finding types to a vulnerability finding.
        """
        if vuln_finding.type != FindingType.VULNERABILITY:
            return
        
        if other_finding.type == FindingType.OUTDATED:
            if "outdated_info" not in vuln_finding.details:
                vuln_finding.details["outdated_info"] = {
                    "is_outdated": True,
                    "current_version": other_finding.version,
                    "latest_version": other_finding.details.get("fixed_version"),
                    "message": other_finding.description,
                }
        
        elif other_finding.type == FindingType.QUALITY:
            if "quality_info" not in vuln_finding.details:
                quality_issues = other_finding.details.get("quality_issues", [])
                vuln_finding.details["quality_info"] = {
                    "has_quality_issues": True,
                    "issue_count": len(quality_issues),
                    "overall_score": other_finding.details.get("overall_score"),
                    "has_maintenance_issues": other_finding.details.get(
                        "has_maintenance_issues", False
                    ),
                    "quality_finding_id": other_finding.id,
                }
        
        elif other_finding.type == FindingType.LICENSE:
            if "license_info" not in vuln_finding.details:
                vuln_finding.details["license_info"] = {
                    "has_license_issue": True,
                    "license": other_finding.details.get("license"),
                    "category": other_finding.details.get("category"),
                    "license_finding_id": other_finding.id,
                }
        
        elif other_finding.type == FindingType.EOL:
            if "eol_info" not in vuln_finding.details:
                vuln_finding.details["eol_info"] = {
                    "is_eol": True,
                    "eol_date": other_finding.details.get("eol_date"),
                    "cycle": other_finding.details.get("cycle"),
                    "latest_version": other_finding.details.get("fixed_version"),
                    "eol_finding_id": other_finding.id,
                }

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
            result[key] = enrichment.to_dict()
        return result

    def get_license_data(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns detailed license analysis data per package.
        Useful for license compliance reporting.
        """
        return self._license_data

    def _enrich_with_scorecard(self, findings: List[Finding]):
        """
        Enriches non-scorecard findings with scorecard data for the same component.
        This adds maintenance and quality context to vulnerability findings.
        """
        if not self._scorecard_cache:
            return

        for finding in findings:
            # Skip scorecard findings themselves
            if finding.type == FindingType.QUALITY and finding.id.startswith(
                "SCORECARD-"
            ):
                continue

            # Try to find scorecard data for this component
            component_key = (
                f"{finding.component}@{finding.version}"
                if finding.version
                else finding.component
            )
            scorecard_data = self._scorecard_cache.get(component_key)

            # Also try without version
            if not scorecard_data and finding.component:
                for key, data in self._scorecard_cache.items():
                    if key.startswith(f"{finding.component}@"):
                        scorecard_data = data
                        break

            if scorecard_data:
                # Add scorecard context to finding details
                finding.details["scorecard_context"] = {
                    "overall_score": scorecard_data.get("overall_score"),
                    "project_url": scorecard_data.get("project_url"),
                    "critical_issues": scorecard_data.get("critical_issues", []),
                    "maintenance_risk": "Maintained"
                    in scorecard_data.get("critical_issues", []),
                    "has_vulnerabilities_issue": "Vulnerabilities"
                    in scorecard_data.get("critical_issues", []),
                }

                # If this is a vulnerability in a poorly maintained package, consider upgrading severity
                if finding.type == FindingType.VULNERABILITY:
                    score = scorecard_data.get("overall_score", 10)
                    critical = scorecard_data.get("critical_issues", [])

                    # Add warning flags
                    if score < 4.0 or "Maintained" in critical:
                        finding.details["maintenance_warning"] = True
                        finding.details["maintenance_warning_text"] = (
                            "This package has a low OpenSSF Scorecard score ({:.1f}/10) "
                            "which may indicate maintenance or security concerns.".format(
                                score
                            )
                        )

    def _normalize_trufflehog(self, result: Dict[str, Any], source: str = None):
        # TruffleHog structure: {"findings": [TruffleHogFinding objects]}
        # The result dict is expected to contain a list of findings under "findings" key
        for finding in result.get("findings", []):
            # finding is a dict (from Pydantic model dump)

            # Extract file path
            file_path = "unknown"
            if finding.get("SourceMetadata") and "Data" in finding["SourceMetadata"]:
                # Filesystem mode
                data = finding["SourceMetadata"]["Data"]
                if "Filesystem" in data and "file" in data["Filesystem"]:
                    file_path = data["Filesystem"]["file"]
                elif "Git" in data and "file" in data["Git"]:
                    file_path = data["Git"]["file"]

            detector = finding.get("DetectorType", "Generic Secret")

            # Create a unique ID based on detector, file path, and secret hash
            # Storing the raw secret in the ID is avoided.
            # Using Raw secret hash for deduplication is good.
            raw_secret = finding.get("Raw", "")
            secret_hash = (
                hashlib.md5(raw_secret.encode()).hexdigest() if raw_secret else "nohash"
            )

            finding_id = f"SECRET-{detector}-{secret_hash[:8]}"

            secret_details: SecretDetails = {
                "detector": detector,
                "decoder": finding.get("DecoderName"),
                "verified": finding.get("Verified"),
                # Do NOT store Raw secret in details unless encrypted/redacted.
                # TruffleHog provides "Redacted" field.
                "redacted": finding.get("Redacted"),
            }

            self._add_finding(
                Finding(
                    id=finding_id,
                    type=FindingType.SECRET,
                    severity=Severity.CRITICAL,
                    component=file_path,
                    version="",  # No version for secrets in files
                    description=f"Secret detected: {detector}",
                    scanners=["trufflehog"],
                    details=secret_details,
                ),
                source=source,
            )

    def _parse_version_key(self, v: str):
        """Helper to parse version string into a comparable tuple."""
        # Remove common prefixes
        v = v.lower()
        if v.startswith("v"):
            v = v[1:]

        # Split by non-alphanumeric characters
        parts = []
        for part in re.split(r"[^a-z0-9]+", v):
            if not part:
                continue
            if part.isdigit():
                parts.append(int(part))
            else:
                parts.append(part)
        return tuple(parts)

    def _calculate_aggregated_fixed_version(
        self, fixed_versions_list: List[str]
    ) -> str:
        """
        Calculates the best fixed version(s) considering multiple vulnerabilities and major versions.
        Input: List of fixed version strings (e.g. ["1.2.5, 2.0.1", "1.2.6"])
        Output: String (e.g. "1.2.6, 2.0.1")
        """
        if not fixed_versions_list:
            return None

        # 1. Parse all available fixes
        # Structure: { MajorVersion: { VulnIndex: [VersionTuple, OriginalString] } }
        major_buckets = {}

        for i, fv_str in enumerate(fixed_versions_list):
            # Split by comma to handle "1.2.5, 2.0.1"
            candidates = [c.strip() for c in fv_str.split(",") if c.strip()]

            for cand in candidates:
                try:
                    parsed = self._parse_version_key(cand)
                    if not parsed:
                        continue

                    # Use first element as major version bucket key
                    # If it's a string (e.g. 'release'), it goes to its own bucket
                    major = parsed[0] if len(parsed) > 0 else 0

                    if major not in major_buckets:
                        major_buckets[major] = {}

                    if i not in major_buckets[major]:
                        major_buckets[major][i] = []

                    major_buckets[major][i].append((parsed, cand))
                except Exception:
                    continue

        # 2. Find valid major versions (must cover ALL vulnerabilities)
        valid_majors = []
        num_vulns = len(fixed_versions_list)

        for major, vulns_map in major_buckets.items():
            # Check if this major version has a fix for every vulnerability
            if len(vulns_map) == num_vulns:
                # Find the MAX required version for this major line
                max_ver_tuple = None
                max_ver_str = None

                for vuln_idx, fixes in vulns_map.items():
                    # Sort fixes for this vuln by version tuple (ascending)
                    # We pick the lowest version that fixes the vuln (conservative approach)
                    fixes.sort(key=lambda x: x[0])
                    best_fix_for_vuln = fixes[0]

                    if max_ver_tuple is None or best_fix_for_vuln[0] > max_ver_tuple:
                        max_ver_tuple = best_fix_for_vuln[0]
                        max_ver_str = best_fix_for_vuln[1]

                valid_majors.append((major, max_ver_tuple, max_ver_str))

        # 3. Sort and format results
        if not valid_majors:
            return None

        # Sort by major version (try to sort numerically if possible)
        try:
            valid_majors.sort(
                key=lambda x: x[0] if isinstance(x[0], int) else str(x[0])
            )
        except TypeError:
            valid_majors.sort(key=lambda x: str(x[0]))

        return ", ".join([vm[2] for vm in valid_majors])

    def _resolve_fixed_versions(self, versions: List[str]) -> str:
        """
        Resolves the best fixed version(s) considering multiple vulnerabilities and major versions.
        Replaces legacy _get_latest_version.
        """
        return self._calculate_aggregated_fixed_version(versions)

    def _normalize_component(self, component: str) -> str:
        if not component:
            return "unknown"
        return component.strip().lower()

    def _is_same_component_name(self, name1: str, name2: str) -> bool:
        """
        Checks if two component names likely refer to the same software.
        e.g. 'postgresql' and 'org.postgresql:postgresql' -> True
        """
        n1 = name1.lower()
        n2 = name2.lower()
        if n1 == n2:
            return True

        # Check for group:artifact vs artifact
        if ":" in n1 and n1.endswith(f":{n2}"):
            return True
        if ":" in n2 and n2.endswith(f":{n1}"):
            return True

        # Check for group/artifact vs artifact (e.g. @angular/core vs core - careful!)
        # We only allow this if the "short" name is NOT generic?
        # Actually, if they share the same VERSION and VULNERABILITIES, it is much safer to assume identity.
        # So we can be a bit more lenient here because this check is only called when other factors match.

        if "/" in n1 and n1.endswith(f"/{n2}"):
            return True
        if "/" in n2 and n2.endswith(f"/{n1}"):
            return True

        return False

    def _merge_vulnerability_into_list(
        self, target_list: List[Dict[str, Any]], source_entry: Dict[str, Any]
    ):
        """
        Merges a source vulnerability entry into a target list, handling deduplication by ID and Aliases.
        """
        match_found = False
        s_ids = set([source_entry["id"]] + source_entry.get("aliases", []))

        for tv in target_list:
            t_ids = set([tv["id"]] + tv.get("aliases", []))

            if not s_ids.isdisjoint(t_ids):
                # Match found! Merge details
                match_found = True

                # Merge Scanners
                tv["scanners"] = list(
                    set(tv.get("scanners", []) + source_entry.get("scanners", []))
                )

                # Merge Aliases
                all_aliases = set(
                    tv.get("aliases", []) + source_entry.get("aliases", [])
                )
                if source_entry["id"] != tv["id"]:
                    all_aliases.add(source_entry["id"])
                tv["aliases"] = list(all_aliases)

                # Merge Severity (Max)
                tv_sev_val = SEVERITY_ORDER.get(tv.get("severity", "UNKNOWN"), 0)
                sv_sev_val = SEVERITY_ORDER.get(
                    source_entry.get("severity", "UNKNOWN"), 0
                )
                if sv_sev_val > tv_sev_val:
                    tv["severity"] = source_entry["severity"]

                # Description merge (prefer longer)
                if len(source_entry.get("description", "")) > len(
                    tv.get("description", "")
                ):
                    tv["description"] = source_entry["description"]
                    tv["description_source"] = source_entry.get(
                        "description_source", "unknown"
                    )

                # Fixed version merge (prefer non-empty)
                if not tv.get("fixed_version") and source_entry.get("fixed_version"):
                    tv["fixed_version"] = source_entry["fixed_version"]

                # CVSS merge (prefer higher)
                if source_entry.get("cvss_score") and (
                    not tv.get("cvss_score")
                    or source_entry["cvss_score"] > tv["cvss_score"]
                ):
                    tv["cvss_score"] = source_entry["cvss_score"]
                    tv["cvss_vector"] = source_entry.get("cvss_vector")

                # References merge
                tv_refs = tv.get("references", [])
                sv_refs = source_entry.get("references", [])
                tv["references"] = list(set(tv_refs + sv_refs))

                # Merge other details (selectively)
                # We check both top-level and nested details for these fields
                for key in ["cwe_ids", "published_date", "last_modified_date"]:
                    # Check source details
                    val = source_entry.get("details", {}).get(key)
                    if not val:
                        continue

                    # Ensure target has details dict
                    if "details" not in tv:
                        tv["details"] = {}

                    # Update if missing in target
                    if key not in tv["details"] or not tv["details"][key]:
                        tv["details"][key] = val

                break

        if not match_found:
            target_list.append(source_entry)

    def _merge_findings_data(self, target: Finding, source: Finding):
        """Merges data from source finding into target finding."""
        # 1. Scanners
        target.scanners = list(set(target.scanners + source.scanners))

        # 2. Severity (Max)
        t_sev = SEVERITY_ORDER.get(target.severity, 0)
        s_sev = SEVERITY_ORDER.get(source.severity, 0)
        if s_sev > t_sev:
            target.severity = source.severity

        # 3. Found In
        target.found_in = list(set(target.found_in + source.found_in))

        # 4. Aliases
        target.aliases = list(set(target.aliases + source.aliases))
        if source.id != target.id:
            if source.id not in target.aliases:
                target.aliases.append(source.id)

        # 5. Details (Vulnerabilities)
        # Merge vulnerabilities list, handling aliases to avoid duplicates
        t_vulns_list = target.details.get("vulnerabilities", [])
        s_vulns_list = source.details.get("vulnerabilities", [])

        for sv in s_vulns_list:
            self._merge_vulnerability_into_list(t_vulns_list, sv)

        target.details["vulnerabilities"] = t_vulns_list

        # Recalculate top-level fixed version
        fvs = [
            v.get("fixed_version")
            for v in target.details["vulnerabilities"]
            if v.get("fixed_version")
        ]
        target.details["fixed_version"] = self._resolve_fixed_versions(fvs)

    def _normalize_version(self, version: str) -> str:
        if not version:
            return "unknown"
        v = version.strip().lower()
        # Handle go1.25.4 -> 1.25.4
        if v.startswith("go") and len(v) > 2 and v[2].isdigit():
            return v[2:]
        # Handle v1.25.4 -> 1.25.4
        if v.startswith("v") and len(v) > 1 and v[1].isdigit():
            return v[1:]
        return v

    def _add_finding(self, finding: Finding, source: str = None):
        """
        Adds a finding to the map, merging if it already exists.
        """
        if finding.type == FindingType.VULNERABILITY:
            self._add_vulnerability_finding(finding, source)
        elif finding.type == FindingType.QUALITY:
            self._add_quality_finding(finding, source)
        else:
            self._add_generic_finding(finding, source)

    def _add_vulnerability_finding(self, finding: Finding, source: str = None):
        # Normalize keys
        raw_comp = finding.component if finding.component else "unknown"
        comp_key = self._normalize_component(raw_comp)

        # Normalize version (handle go1.25.4 vs 1.25.4)
        raw_version = finding.version if finding.version else "unknown"
        version_key = self._normalize_version(raw_version)

        # Primary key for the AGGREGATED finding (The Package)
        agg_key = f"AGG:VULN:{comp_key}:{version_key}"

        # Prepare the vulnerability entry for the details list
        vuln_entry: VulnerabilityEntry = {
            "id": finding.id,
            "severity": finding.severity,
            "description": finding.description,
            "description_source": (
                finding.scanners[0] if finding.scanners else "unknown"
            ),
            "fixed_version": (
                str(finding.details.get("fixed_version"))
                if finding.details.get("fixed_version")
                else None
            ),
            "cvss_score": (
                float(finding.details.get("cvss_score"))
                if finding.details.get("cvss_score")
                else None
            ),
            "cvss_vector": (
                str(finding.details.get("cvss_vector"))
                if finding.details.get("cvss_vector")
                else None
            ),
            "references": finding.details.get("references", []) or [],
            "aliases": finding.aliases or [],
            "scanners": finding.scanners or [],
            "source": source,
            "details": finding.details or {},  # nested details
        }

        if agg_key in self.findings:
            existing = self.findings[agg_key]

            # 1. Update Scanners of the aggregate
            existing.scanners = list(set(existing.scanners + finding.scanners))

            # 2. Update Severity of the aggregate (Max of all vulns)
            existing_severity_val = SEVERITY_ORDER.get(existing.severity, 0)
            new_severity_val = SEVERITY_ORDER.get(finding.severity, 0)
            if new_severity_val > existing_severity_val:
                existing.severity = finding.severity

            # 3. Merge into vulnerabilities list
            vuln_list: List[VulnerabilityEntry] = existing.details.get(
                "vulnerabilities", []
            )

            self._merge_vulnerability_into_list(vuln_list, vuln_entry)

            existing.details["vulnerabilities"] = vuln_list

            # Update description
            count = len(vuln_list)
            # existing.description = f"Found {count} vulnerabilities in {finding.component}"
            # We don't set a description for aggregated findings anymore, as it's just a container.
            # The frontend will handle the display.
            existing.description = ""

            # Update found_in
            if source and source not in existing.found_in:
                existing.found_in.append(source)

            # Update top-level fixed_version
            # Only consider vulnerabilities that actually HAVE a fixed version
            fvs = [v.get("fixed_version") for v in vuln_list if v.get("fixed_version")]

            if not fvs:
                existing.details["fixed_version"] = None
            else:
                # Calculate the best fixed version(s) covering all vulnerabilities
                existing.details["fixed_version"] = self._resolve_fixed_versions(fvs)

        else:
            # Create new Aggregate Finding
            agg_details: VulnerabilityAggregatedDetails = {
                "vulnerabilities": [vuln_entry],
                "fixed_version": (
                    str(finding.details.get("fixed_version"))
                    if finding.details.get("fixed_version")
                    else None
                ),
            }

            agg_finding = Finding(
                id=f"{finding.component}:{finding.version}",
                type=FindingType.VULNERABILITY,
                severity=finding.severity,
                component=finding.component,
                version=finding.version,
                description="",  # No description for aggregated findings
                scanners=finding.scanners,
                details=agg_details,
                found_in=[source] if source else [],
            )
            self.findings[agg_key] = agg_finding

    def _add_quality_finding(self, finding: Finding, source: str = None):
        """
        Adds a quality finding to the map, aggregating multiple quality issues
        (scorecard, maintainer_risk, etc.) for the same component+version.
        Structure mirrors vulnerability aggregation with a quality_issues list.
        """
        # Normalize keys
        raw_comp = finding.component if finding.component else "unknown"
        comp_key = self._normalize_component(raw_comp)

        # Normalize version
        raw_version = finding.version if finding.version else "unknown"
        version_key = self._normalize_version(raw_version)

        # Primary key for the AGGREGATED quality finding
        agg_key = f"AGG:QUALITY:{comp_key}:{version_key}"

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
            existing_severity_val = SEVERITY_ORDER.get(existing.severity, 0)
            new_severity_val = SEVERITY_ORDER.get(finding.severity, 0)
            if new_severity_val > existing_severity_val:
                existing.severity = finding.severity

            # 3. Add to quality_issues list (check for duplicates by ID)
            quality_list: List[QualityEntry] = existing.details.get(
                "quality_issues", []
            )
            existing_ids = {q.get("id") for q in quality_list}

            if finding.id not in existing_ids:
                quality_list.append(quality_entry)
                existing.details["quality_issues"] = quality_list
                existing.details["issue_count"] = len(quality_list)

            # 4. Update overall_score if this is a scorecard finding
            if (
                issue_type == "scorecard"
                and finding.details.get("overall_score") is not None
            ):
                existing.details["overall_score"] = finding.details.get("overall_score")

            # 5. Update maintenance flag
            if has_maintenance:
                existing.details["has_maintenance_issues"] = True

            # Update found_in
            if source and source not in existing.found_in:
                existing.found_in.append(source)

            # Update description to reflect issue count
            self._update_quality_description(existing)

        else:
            # Create new Aggregate Quality Finding
            agg_details: QualityAggregatedDetails = {
                "quality_issues": [quality_entry],
                "overall_score": (
                    finding.details.get("overall_score")
                    if issue_type == "scorecard"
                    else None
                ),
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

    def _update_quality_description(self, finding: Finding):
        """Updates the description of an aggregated quality finding."""
        quality_issues = finding.details.get("quality_issues", [])
        count = len(quality_issues)

        if count == 0:
            finding.description = "Quality issues detected"
            return

        if count == 1:
            # Use the original description from the single issue
            finding.description = quality_issues[0].get(
                "description", "Quality issue detected"
            )
            return

        # Multiple issues - create summary
        parts = []

        # Check for scorecard
        scorecard_issues = [q for q in quality_issues if q.get("type") == "scorecard"]
        if scorecard_issues:
            score = scorecard_issues[0].get("details", {}).get("overall_score")
            if score is not None:
                parts.append(f"Scorecard: {score:.1f}/10")

        # Check for maintainer risk
        maint_issues = [q for q in quality_issues if q.get("type") == "maintainer_risk"]
        if maint_issues:
            risks = maint_issues[0].get("details", {}).get("risks", [])
            if risks:
                parts.append(f"{len(risks)} maintainer risks")

        # Other issues
        other_count = count - len(scorecard_issues) - len(maint_issues)
        if other_count > 0:
            parts.append(f"{other_count} other issues")

        finding.description = " | ".join(parts) if parts else f"{count} quality issues"

    def _add_generic_finding(self, finding: Finding, source: str = None):
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
                lookup_key_alias = (
                    f"{finding.type}:{comp_key}:{finding.version}:{alias}"
                )
                if lookup_key_alias in self.alias_map:
                    existing_key = self.alias_map[lookup_key_alias]
                    break

        if existing_key and existing_key in self.findings:
            existing = self.findings[existing_key]

            # 1. Merge scanners list
            existing.scanners = list(set(existing.scanners + finding.scanners))

            # 2. Merge Severity (keep highest)
            existing_severity_val = SEVERITY_ORDER.get(existing.severity, 0)
            new_severity_val = SEVERITY_ORDER.get(finding.severity, 0)

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

    def _normalize_trivy(self, result: Dict[str, Any], source: str = None):
        # Trivy structure: {"Results": [{"Vulnerabilities": [...]}]}
        if "Results" not in result:
            return

        for target in result.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                # Extract extra details
                references = vuln.get("References", [])
                published_date = vuln.get("PublishedDate")
                last_modified_date = vuln.get("LastModifiedDate")
                cwe_ids = vuln.get("CweIDs", [])

                # Extract aliases from references
                aliases = set()
                vuln_id = vuln.get("VulnerabilityID")

                for ref in references:
                    match = re.search(r"(CVE-\d{4}-\d{4,})", ref)
                    if match:
                        cve = match.group(1)
                        if cve != vuln_id:
                            aliases.add(cve)

                # ID Normalization: Prefer CVE if available in aliases
                aliases_list = list(aliases)
                cve_alias = next(
                    (a for a in aliases_list if a.startswith("CVE-")), None
                )

                if cve_alias and vuln_id and not vuln_id.startswith("CVE-"):
                    if vuln_id not in aliases_list:
                        aliases_list.append(vuln_id)
                    vuln_id = cve_alias

                # CVSS Parsing
                cvss_score = None
                cvss_vector = None
                if "CVSS" in vuln:
                    # Trivy CVSS structure varies, usually {"nvd": {"V3Score": ...}, "redhat": ...}
                    # We prefer NVD V3, then V2, then Vendor
                    for source_cvss in ["nvd", "redhat", "ghsa", "bitnami"]:
                        if source_cvss in vuln["CVSS"]:
                            data = vuln["CVSS"][source_cvss]
                            if "V3Score" in data:
                                cvss_score = data["V3Score"]
                                cvss_vector = data.get("V3Vector")
                                break
                            elif "V2Score" in data and cvss_score is None:
                                cvss_score = data["V2Score"]
                                cvss_vector = data.get("V2Vector")

                # Construct description: Title + Description for maximum context
                title = vuln.get("Title", "").strip()
                desc = vuln.get("Description", "").strip()

                if title and desc:
                    # Check if title is just a truncated or full version of the description
                    clean_title = title
                    if title.endswith("..."):
                        clean_title = title[:-3].strip()

                    if clean_title in desc:
                        final_desc = desc
                    else:
                        final_desc = f"{title}\n\n{desc}"
                else:
                    final_desc = desc or title or ""

                self._add_finding(
                    Finding(
                        id=vuln_id,
                        type=FindingType.VULNERABILITY,
                        severity=Severity(vuln.get("Severity", "UNKNOWN").upper()),
                        component=vuln.get("PkgName"),
                        version=vuln.get("InstalledVersion"),
                        description=final_desc,
                        scanners=["trivy"],
                        details={
                            "fixed_version": vuln.get("FixedVersion"),
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "references": references,
                            "published_date": published_date,
                            "last_modified_date": last_modified_date,
                            "cwe_ids": cwe_ids,
                            "layer_id": vuln.get("Layer", {}).get("Digest"),
                        },
                        aliases=aliases_list,
                    ),
                    source=source,
                )

    def _normalize_grype(self, result: Dict[str, Any], source: str = None):
        # Grype structure: {"matches": [{"vulnerability": {...}, "artifact": {...}}]}
        for match in result.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            # ID Normalization: Prefer CVE if available in aliases
            vuln_id = vuln.get("id")
            aliases = [
                r.get("id")
                for r in vuln.get("relatedVulnerabilities", [])
                if r.get("id")
            ]

            # If current ID is GHSA/GO/etc and a CVE exists in aliases, use CVE as primary ID
            cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
            if cve_alias and vuln_id and not vuln_id.startswith("CVE-"):
                if vuln_id not in aliases:
                    aliases.append(vuln_id)
                vuln_id = cve_alias

            # CVSS Parsing
            cvss_score = None
            cvss_vector = None
            if "cvss" in vuln:
                # Grype CVSS is a list of objects
                # We look for the highest version (3.1 > 3.0 > 2.0)
                best_cvss = None
                for cvss in vuln["cvss"]:
                    version = cvss.get("version", "0.0")
                    if best_cvss is None or version > best_cvss.get("version", "0.0"):
                        best_cvss = cvss

                if best_cvss:
                    cvss_score = float(best_cvss.get("metrics", {}).get("baseScore", 0))
                    cvss_vector = best_cvss.get("vector")

            self._add_finding(
                Finding(
                    id=vuln_id,
                    type=FindingType.VULNERABILITY,
                    severity=Severity(vuln.get("severity", "UNKNOWN").upper()),
                    component=artifact.get("name"),
                    version=artifact.get("version"),
                    description=vuln.get("description", ""),
                    scanners=["grype"],
                    details={
                        "fixed_version": ", ".join(
                            vuln.get("fix", {}).get("versions", [])
                        ),
                        "datasource": vuln.get("dataSource"),
                        "urls": vuln.get("urls", []),
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "namespace": vuln.get("namespace"),
                    },
                    aliases=aliases,
                ),
                source=source,
            )

    def _normalize_osv(self, result: Dict[str, Any], source: str = None):
        # OSV structure: {"osv_vulnerabilities": [{"component":..., "vulnerabilities": [...]}]}
        for item in result.get("osv_vulnerabilities", []):
            comp_name = item.get("component")
            comp_version = item.get("version")

            for vuln in item.get("vulnerabilities", []):
                # 1. Determine Severity
                severity = "UNKNOWN"

                # Check database_specific (common in GHSA)
                if (
                    "database_specific" in vuln
                    and "severity" in vuln["database_specific"]
                ):
                    severity = vuln["database_specific"]["severity"].upper()

                # Map OSV specific terms
                if severity == "MODERATE":
                    severity = "MEDIUM"

                # 2. Extract Fixed Version
                fixed_version = None
                if "affected" in vuln:
                    for affected in vuln["affected"]:
                        # We assume the first fixed event we find is relevant
                        if "ranges" in affected:
                            for r in affected["ranges"]:
                                if "events" in r:
                                    for event in r["events"]:
                                        if "fixed" in event:
                                            fixed_version = event["fixed"]
                                            break
                                if fixed_version:
                                    break
                        if fixed_version:
                            break

                # 3. ID Normalization: Prefer CVE if available in aliases
                vuln_id = vuln.get("id")
                aliases = vuln.get("aliases", [])

                # Handle prefixed CVEs like DEBIAN-CVE-2025-10148
                if vuln_id and "CVE-" in vuln_id and not vuln_id.startswith("CVE-"):
                    # Try to extract CVE
                    match = re.search(r"(CVE-\d{4}-\d{4,})", vuln_id)
                    if match:
                        cve_extracted = match.group(1)
                        if vuln_id not in aliases:
                            aliases.append(vuln_id)
                        vuln_id = cve_extracted

                # If current ID is GHSA/GO/etc and a CVE exists in aliases, use CVE as primary ID
                cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
                if cve_alias and vuln_id and not vuln_id.startswith("CVE-"):
                    # Add original ID to aliases list to preserve it
                    if vuln_id not in aliases:
                        aliases.append(vuln_id)
                    vuln_id = cve_alias

                self._add_finding(
                    Finding(
                        id=vuln_id,
                        type=FindingType.VULNERABILITY,
                        severity=Severity(severity),
                        component=comp_name,
                        version=comp_version,
                        description=vuln.get("summary") or vuln.get("details", ""),
                        scanners=["osv"],
                        details={
                            "fixed_version": fixed_version,
                            "references": vuln.get("references"),
                            "published": vuln.get("published"),
                            "modified": vuln.get("modified"),
                            "osv_url": f"https://osv.dev/vulnerability/{vuln.get('id')}",
                        },
                        aliases=aliases,
                    ),
                    source=source,
                )

    def _normalize_outdated(self, result: Dict[str, Any], source: str = None):
        for item in result.get("outdated_dependencies", []):
            self._add_finding(
                Finding(
                    id=f"OUTDATED-{item['component']}",
                    type=FindingType.OUTDATED,
                    severity=Severity(item.get("severity", "INFO")),
                    component=item.get("component"),
                    version=item.get("current_version"),
                    description=item.get("message"),
                    scanners=["outdated_packages"],
                    details={"fixed_version": item.get("latest_version")},
                ),
                source=source,
            )

    def _normalize_license(self, result: Dict[str, Any], source: str = None):
        for item in result.get("license_issues", []):
            # Map severity strings to enum (handle INFO as LOW since INFO might not exist)
            severity_str = item.get("severity", "MEDIUM").upper()
            if severity_str == "INFO":
                severity = Severity.LOW
            else:
                severity = Severity(severity_str)

            component = item.get("component")
            version = item.get("version")

            # Enrich dependency with license data (aggregation)
            if component and version:
                self._enrich_from_license_scanner(component, version, item)

            self._add_finding(
                Finding(
                    id=f"LIC-{item['license']}",
                    type=FindingType.LICENSE,
                    severity=severity,
                    component=component,
                    version=version,
                    description=item.get("message"),
                    scanners=["license_compliance"],
                    details={
                        "license": item.get("license"),
                        "license_url": item.get("license_url"),
                        "category": item.get("category"),
                        "explanation": item.get("explanation"),
                        "recommendation": item.get("recommendation"),
                        "obligations": item.get("obligations", []),
                        "risks": item.get("risks", []),
                        "purl": item.get("purl"),
                    },
                ),
                source=source,
            )

    def _normalize_scorecard(self, result: Dict[str, Any], source: str = None):
        """
        Process OpenSSF Scorecard results and package metadata from deps_dev scanner.
        Also stores scorecard data for component enrichment.
        """
        # Process package metadata (not findings, but enrichment data)
        for key, metadata in result.get("package_metadata", {}).items():
            # Populate the DependencyEnrichment structure
            name = metadata.get("name", "")
            version = metadata.get("version", "")
            if name and version:
                self._enrich_from_deps_dev(name, version, metadata)

        # Process scorecard issues (these become findings)
        for item in result.get("scorecard_issues", []):
            scorecard = item.get("scorecard", {})
            overall = scorecard.get("overallScore", 0)
            failed_checks = item.get("failed_checks", [])
            critical_issues = item.get("critical_issues", [])
            project_url = item.get("project_url", "")
            component = item.get("component", "")
            version = item.get("version", "")

            # Store scorecard data for component enrichment
            # This allows other findings to reference scorecard data
            component_key = f"{component}@{version}" if version else component
            self._scorecard_cache[component_key] = {
                "overall_score": overall,
                "failed_checks": failed_checks,
                "critical_issues": critical_issues,
                "project_url": project_url,
                "checks": scorecard.get("checks", []),
            }

            # Determine severity based on score and critical issues
            if (
                overall < 3.0
                or "Maintained" in critical_issues
                or "Vulnerabilities" in critical_issues
            ):
                severity = Severity.HIGH
            elif overall < 5.0 or critical_issues:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Build detailed description
            description_parts = [f"OpenSSF Scorecard score: {overall:.1f}/10"]

            if critical_issues:
                description_parts.append(
                    f"Critical issues: {', '.join(critical_issues)}"
                )

            if failed_checks:
                failed_names = [
                    f"{c['name']} ({c['score']}/10)" for c in failed_checks[:3]
                ]
                description_parts.append(f"Failed checks: {', '.join(failed_names)}")
                if len(failed_checks) > 3:
                    description_parts[-1] += f" (+{len(failed_checks) - 3} more)"

            description = ". ".join(description_parts)

            # Build recommendation based on issues
            recommendations = []
            for check in failed_checks:
                check_name = check.get("name", "")
                if check_name == "Maintained":
                    recommendations.append(
                        "Consider finding an actively maintained alternative"
                    )
                elif check_name == "Vulnerabilities":
                    recommendations.append("Check for and apply security patches")
                elif check_name == "CII-Best-Practices":
                    recommendations.append(
                        "Package doesn't follow OpenSSF best practices"
                    )
                elif check_name == "Code-Review":
                    recommendations.append(
                        "Limited code review process - higher risk of unreviewed changes"
                    )
                elif check_name == "Fuzzing":
                    recommendations.append("No fuzzing - potential undiscovered bugs")
                elif check_name == "SAST":
                    recommendations.append(
                        "No static analysis - potential code quality issues"
                    )

            self._add_finding(
                Finding(
                    id=f"SCORECARD-{component}",
                    type=FindingType.QUALITY,
                    severity=severity,
                    component=component,
                    version=version,
                    description=description,
                    scanners=["deps_dev"],
                    details={
                        "scorecard": scorecard,
                        "overall_score": overall,
                        "failed_checks": failed_checks,
                        "critical_issues": critical_issues,
                        "project_url": project_url,
                        "repository": scorecard.get("repository"),
                        "scorecard_date": scorecard.get("date"),
                        "recommendation": (
                            " • ".join(recommendations) if recommendations else None
                        ),
                        "checks_summary": {
                            check.get("name"): check.get("score")
                            for check in scorecard.get("checks", [])
                            if check.get("score", -1) >= 0
                        },
                    },
                ),
                source=source,
            )

    def _normalize_malware(self, result: Dict[str, Any], source: str = None):
        for item in result.get("malware_issues", []):
            malware_info = item.get("malware_info", {})
            threats = malware_info.get("threats", [])

            description = "Potential malware detected"
            if threats:
                description = f"Malware detected: {', '.join(threats)}"
            elif malware_info.get("description"):
                description = f"Malware detected: {malware_info.get('description')}"

            self._add_finding(
                Finding(
                    id=f"MALWARE-{item['component']}",
                    type=FindingType.MALWARE,
                    severity=Severity.CRITICAL,
                    component=item.get("component"),
                    version=item.get("version"),
                    description=description,
                    scanners=["os_malware"],
                    details={
                        "info": malware_info,
                        "threats": threats,
                        "reference": malware_info.get("reference"),
                    },
                ),
                source=source,
            )

    def _normalize_eol(self, result: Dict[str, Any], source: str = None):
        for item in result.get("eol_issues", []):
            eol_info = item.get("eol_info", {})
            eol_date = eol_info.get("eol")
            cycle = eol_info.get("cycle")
            latest = eol_info.get("latest")

            self._add_finding(
                Finding(
                    id=f"EOL-{item['component']}-{cycle}",
                    type=FindingType.EOL,
                    severity=Severity.HIGH,
                    component=item.get("component"),
                    version=item.get("version"),
                    description=f"End of Life reached on {eol_date} (Cycle {cycle}). Latest: {latest}",
                    scanners=["end_of_life"],
                    details={
                        "fixed_version": latest,
                        "eol_date": eol_date,
                        "cycle": cycle,
                        "link": eol_info.get("link"),
                        "lts": eol_info.get("lts"),
                    },
                ),
                source=source,
            )

    def _normalize_typosquatting(self, result: Dict[str, Any], source: str = None):
        for item in result.get("typosquatting_issues", []):
            similarity = item.get("similarity", 0)
            imitated = item.get("imitated_package")

            self._add_finding(
                Finding(
                    id=f"TYPO-{item['component']}",
                    type=FindingType.MALWARE,  # Typosquatting is a form of malware/attack
                    severity=Severity.CRITICAL,
                    component=item.get("component"),
                    version=item.get("version"),
                    description=f"Possible typosquatting detected! '{item.get('component')}' is {similarity*100:.1f}% similar to popular package '{imitated}'",
                    scanners=["typosquatting"],
                    details={"imitated_package": imitated, "similarity": similarity},
                ),
                source=source,
            )

    def _normalize_opengrep(self, result: Dict[str, Any], source: str = None):
        # OpenGrep structure: {"findings": [OpenGrepFinding objects]}
        for finding in result.get("findings", []):
            # finding is a dict
            check_id = finding.get("check_id", "unknown-check")
            path = finding.get("path", "unknown")
            extra = finding.get("extra", {})

            severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

            severity = severity_map.get(extra.get("severity"), "MEDIUM")
            message = extra.get("message", "No description provided")

            # Create unique ID
            finding_hash = hashlib.md5(
                f"{check_id}:{path}:{message}".encode()
            ).hexdigest()
            finding_id = f"SAST-{finding_hash[:8]}"

            self._add_finding(
                Finding(
                    id=finding_id,
                    type=FindingType.SAST,
                    severity=Severity(severity),
                    component=path,
                    version="",
                    description=message,
                    scanners=["opengrep"],
                    details={
                        "check_id": check_id,
                        "start": finding.get("start"),
                        "end": finding.get("end"),
                        "metadata": extra.get("metadata"),
                    },
                ),
                source=source,
            )

    def _normalize_kics(self, result: Dict[str, Any], source: str = None):
        # KICS structure: {"queries": [{"query_name": "...", "files": [...]}]}
        for query in result.get("queries", []):
            severity = query.get("severity", "INFO").upper()

            query_id = query.get("query_id")
            query_name = query.get("query_name")
            description = query.get("description")
            category = query.get("category")

            for file_obj in query.get("files", []):
                file_name = file_obj.get("file_name")
                line = file_obj.get("line")

                self._add_finding(
                    Finding(
                        id=query_id,
                        type=FindingType.IAC,  # Using IAC for KICS
                        severity=Severity(severity),
                        component=file_name,
                        version="",
                        description=f"{query_name}: {description}",
                        scanners=["kics"],
                        details={
                            "category": category,
                            "platform": query.get("platform"),
                            "line": line,
                            "issue_type": file_obj.get("issue_type"),
                            "expected_value": file_obj.get("expected_value"),
                            "actual_value": file_obj.get("actual_value"),
                        },
                    ),
                    source=source,
                )

    def _normalize_bearer(self, result: Dict[str, Any], source: str = None):
        findings_data = result.get("findings", {})

        all_findings = []
        if isinstance(findings_data, list):
            all_findings = findings_data
        elif isinstance(findings_data, dict):
            # If it's a dict, it might be grouped by severity or rule
            # We'll flatten it
            for key, val in findings_data.items():
                if isinstance(val, list):
                    all_findings.extend(val)

        for f in all_findings:
            # Extract fields
            severity = f.get("severity", "UNKNOWN").upper()
            file_path = f.get("filename") or f.get("file") or "unknown"
            line = f.get("line_number") or f.get("line")
            rule_id = f.get("rule_id") or f.get("rule")
            message = f.get("message") or f.get("description") or "Security issue found"

            # Create ID
            finding_hash = hashlib.md5(
                f"{rule_id}:{file_path}:{line}".encode()
            ).hexdigest()
            finding_id = f"BEARER-{finding_hash[:8]}"

            self._add_finding(
                Finding(
                    id=finding_id,
                    type=FindingType.SAST,
                    severity=Severity(severity),
                    component=file_path,
                    version="",
                    description=message,
                    scanners=["bearer"],
                    details={
                        "rule_id": rule_id,
                        "line": line,
                        "cwe_ids": f.get("cwe_ids", []),
                        "documentation": f.get("documentation_url"),
                    },
                ),
                source=source,
            )

    def _normalize_hash_verification(self, result: Dict[str, Any], source: str = None):
        """Normalize hash verification results into findings."""
        for item in result.get("hash_issues", []):
            self._add_finding(
                Finding(
                    id=f"HASH-{item['component']}-{item['algorithm']}",
                    type=FindingType.MALWARE,  # Hash mismatch is a serious supply chain issue
                    severity=Severity.CRITICAL,
                    component=item.get("component"),
                    version=item.get("version"),
                    description=f"Package integrity check failed! {item.get('message', 'Hash mismatch detected')}",
                    scanners=["hash_verification"],
                    details={
                        "registry": item.get("registry"),
                        "algorithm": item.get("algorithm"),
                        "sbom_hash": item.get("sbom_hash"),
                        "expected_hashes": item.get("expected_hashes", []),
                        "verification_failed": True,
                    },
                ),
                source=source,
            )

    def _normalize_maintainer_risk(self, result: Dict[str, Any], source: str = None):
        """Normalize maintainer risk results into findings."""
        for item in result.get("maintainer_issues", []):
            risks = item.get("risks", [])

            # Create a combined description from all risks
            risk_messages = [r.get("message", "") for r in risks]
            description = (
                "; ".join(risk_messages)
                if risk_messages
                else "Maintainer risk detected"
            )

            self._add_finding(
                Finding(
                    id=f"MAINT-{item['component']}",
                    type=FindingType.QUALITY,  # Supply chain quality issue
                    severity=Severity(item.get("severity", "MEDIUM")),
                    component=item.get("component"),
                    version=item.get("version"),
                    description=description,
                    scanners=["maintainer_risk"],
                    details={
                        "risks": risks,
                        "maintainer_info": item.get("maintainer_info", {}),
                        "risk_count": len(risks),
                    },
                ),
                source=source,
            )
