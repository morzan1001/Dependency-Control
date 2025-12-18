from typing import List, Dict, Any, TypedDict, Optional
import hashlib
import re
from app.models.finding import Finding, Severity, FindingType
from app.schemas.finding import VulnerabilityEntry, SecretDetails, VulnerabilityAggregatedDetails

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0
}

class ResultAggregator:
    def __init__(self):
        self.findings: Dict[str, Finding] = {}
        self.alias_map: Dict[str, str] = {}

    def aggregate(self, analyzer_name: str, result: Dict[str, Any], source: str = None):
        """
        Dispatches the result to the specific normalizer based on analyzer name.
        """
        if not result:
            return

        # Check for scanner errors
        if "error" in result:
            self._add_finding(Finding(
                id=f"SCAN-ERROR-{analyzer_name}",
                type=FindingType.SYSTEM_WARNING,
                severity=Severity.HIGH, # High visibility
                component="Scanner System",
                version="",
                description=f"Scanner '{analyzer_name}' failed: {result.get('error')}",
                scanners=[analyzer_name],
                details={
                    "error_details": result.get("details", result.get("output", "No details provided"))
                }
            ), source=source)
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
            "bearer": self._normalize_bearer
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
            if not vulns: continue
            
            # Create a deterministic key for the set of vulnerabilities
            vuln_key = frozenset(vulns)
            
            key = (f.version, vuln_key)
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
                if i in processed_in_group: continue
                
                f1 = group[i]
                cluster = [f1]
                processed_in_group.add(i)
                
                for j in range(i + 1, len(group)):
                    if j in processed_in_group: continue
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
                        if other == primary: continue
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

        return final_findings

        return results

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
            secret_hash = hashlib.md5(raw_secret.encode()).hexdigest() if raw_secret else "nohash"
            
            finding_id = f"SECRET-{detector}-{secret_hash[:8]}"
            
            secret_details: SecretDetails = {
                "detector": detector,
                "decoder": finding.get("DecoderName"),
                "verified": finding.get("Verified"),
                # Do NOT store Raw secret in details unless encrypted/redacted. 
                # TruffleHog provides "Redacted" field.
                "redacted": finding.get("Redacted")
            }

            self._add_finding(Finding(
                id=finding_id,
                type=FindingType.SECRET,
                severity=Severity.CRITICAL,
                component=file_path,
                version="", # No version for secrets in files
                description=f"Secret detected: {detector}",
                scanners=["trufflehog"],
                details=secret_details
            ), source=source)

    def _parse_version_key(self, v: str):
        """Helper to parse version string into a comparable tuple."""
        # Remove common prefixes
        v = v.lower()
        if v.startswith("v"): v = v[1:]
        
        # Split by non-alphanumeric characters
        parts = []
        for part in re.split(r'[^a-z0-9]+', v):
            if not part: continue
            if part.isdigit():
                parts.append(int(part))
            else:
                parts.append(part)
        return tuple(parts)

    def _calculate_aggregated_fixed_version(self, fixed_versions_list: List[str]) -> str:
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
                    if not parsed: continue
                    
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
            valid_majors.sort(key=lambda x: x[0] if isinstance(x[0], int) else str(x[0]))
        except:
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
        if n1 == n2: return True
        
        # Check for group:artifact vs artifact
        if ":" in n1 and n1.endswith(f":{n2}"): return True
        if ":" in n2 and n2.endswith(f":{n1}"): return True
        
        # Check for group/artifact vs artifact (e.g. @angular/core vs core - careful!)
        # We only allow this if the "short" name is NOT generic? 
        # Actually, if they share the same VERSION and VULNERABILITIES, it is much safer to assume identity.
        # So we can be a bit more lenient here because this check is only called when other factors match.
        
        if "/" in n1 and n1.endswith(f"/{n2}"): return True
        if "/" in n2 and n2.endswith(f"/{n1}"): return True
        
        return False

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
        # We assume they have the same set of vulnerabilities (checked by caller),
        # but we should merge the details of each vulnerability entry.
        t_vulns = {v["id"]: v for v in target.details.get("vulnerabilities", [])}
        s_vulns = source.details.get("vulnerabilities", [])
        
        for sv in s_vulns:
            vid = sv["id"]
            if vid in t_vulns:
                tv = t_vulns[vid]
                # Merge inner details
                tv["scanners"] = list(set(tv.get("scanners", []) + sv.get("scanners", [])))
                tv["aliases"] = list(set(tv.get("aliases", []) + sv.get("aliases", [])))
                
                # Description merge
                if len(sv.get("description", "")) > len(tv.get("description", "")):
                    tv["description"] = sv["description"]
                    tv["description_source"] = sv.get("description_source", "unknown")
                    
                # Fixed version merge (if target missing)
                if not tv.get("fixed_version") and sv.get("fixed_version"):
                    tv["fixed_version"] = sv["fixed_version"]
                    
                # CVSS merge
                if sv.get("cvss_score") and (not tv.get("cvss_score") or sv["cvss_score"] > tv["cvss_score"]):
                    tv["cvss_score"] = sv["cvss_score"]
                    tv["cvss_vector"] = sv.get("cvss_vector")
            else:
                # Should not happen if sets are identical, but for safety
                target.details["vulnerabilities"].append(sv)
        
        # Recalculate top-level fixed version
        fvs = [v.get("fixed_version") for v in target.details["vulnerabilities"] if v.get("fixed_version")]
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
            "description_source": finding.scanners[0] if finding.scanners else "unknown",
            "fixed_version": str(finding.details.get("fixed_version")) if finding.details.get("fixed_version") else None,
            "cvss_score": float(finding.details.get("cvss_score")) if finding.details.get("cvss_score") else None,
            "cvss_vector": str(finding.details.get("cvss_vector")) if finding.details.get("cvss_vector") else None,
            "references": finding.details.get("references", []) or [],
            "aliases": finding.aliases or [],
            "scanners": finding.scanners or [],
            "source": source,
            "details": finding.details or {} # nested details
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
            vuln_list: List[VulnerabilityEntry] = existing.details.get("vulnerabilities", [])
            merged = False
            
            for idx, v in enumerate(vuln_list):
                # Check match by ID or Alias
                v_ids = set([v["id"]] + v.get("aliases", []))
                new_ids = set([finding.id] + finding.aliases)
                
                if not v_ids.isdisjoint(new_ids):
                    # Match found! Merge details
                    v["scanners"] = list(set(v.get("scanners", []) + finding.scanners))
                    
                    all_aliases = set(v.get("aliases", []) + finding.aliases)
                    if finding.id != v["id"]:
                        all_aliases.add(finding.id)
                    v["aliases"] = list(all_aliases)
                    
                    v_sev_val = SEVERITY_ORDER.get(v["severity"], 0)
                    if new_severity_val > v_sev_val:
                        v["severity"] = finding.severity
                    
                    # Merge Fixed Version (prefer non-empty)
                    new_fixed = finding.details.get("fixed_version")
                    current_fixed = v.get("fixed_version")
                    if not current_fixed and new_fixed:
                        v["fixed_version"] = new_fixed
                    
                    # Merge Description (prefer longer description regardless of scanner)
                    new_desc = finding.description
                    current_desc = v.get("description", "")
                    
                    if new_desc:
                        # Update if current is empty OR new one is longer
                        if not current_desc or len(new_desc) > len(current_desc):
                            v["description"] = new_desc
                            v["description_source"] = finding.scanners[0] if finding.scanners else "unknown"

                    # Merge CVSS (prefer higher score)
                    new_cvss = finding.details.get("cvss_score")
                    current_cvss = v.get("cvss_score")
                    if new_cvss:
                        if not current_cvss or new_cvss > current_cvss:
                            v["cvss_score"] = new_cvss
                            if finding.details.get("cvss_vector"):
                                v["cvss_vector"] = finding.details.get("cvss_vector")

                    # Merge References
                    new_refs = finding.details.get("references", [])
                    current_refs = v.get("references", [])
                    v["references"] = list(set(current_refs + new_refs))

                    # Merge other details (selectively)
                    for key in ["cwe_ids", "published_date", "last_modified_date"]:
                        if key in finding.details and finding.details[key]:
                            if key not in v or not v[key]:
                                v[key] = finding.details[key]
                        
                    vuln_list[idx] = v
                    merged = True
                    break
            
            if not merged:
                vuln_list.append(vuln_entry)
                
            existing.details["vulnerabilities"] = vuln_list
            
            # Update description
            count = len(vuln_list)
            existing.description = f"Found {count} vulnerabilities in {finding.component}"
            
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
                "fixed_version": str(finding.details.get("fixed_version")) if finding.details.get("fixed_version") else None
            }

            agg_finding = Finding(
                id=f"{finding.component}:{finding.version}", 
                type=FindingType.VULNERABILITY,
                severity=finding.severity,
                component=finding.component,
                version=finding.version,
                description=f"Found 1 vulnerabilities in {finding.component}",
                scanners=finding.scanners,
                details=agg_details,
                found_in=[source] if source else []
            )
            self.findings[agg_key] = agg_finding

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
                lookup_key_alias = f"{finding.type}:{comp_key}:{finding.version}:{alias}"
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
                    match = re.search(r'(CVE-\d{4}-\d{4,})', ref)
                    if match:
                        cve = match.group(1)
                        if cve != vuln_id:
                            aliases.add(cve)

                # ID Normalization: Prefer CVE if available in aliases
                aliases_list = list(aliases)
                cve_alias = next((a for a in aliases_list if a.startswith("CVE-")), None)
                
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
                    if title in desc:
                        final_desc = desc
                    else:
                        final_desc = f"{title}\n\n{desc}"
                else:
                    final_desc = desc or title or ""

                self._add_finding(Finding(
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
                        "layer_id": vuln.get("Layer", {}).get("Digest")
                    },
                    aliases=aliases_list 
                ), source=source)

    def _normalize_grype(self, result: Dict[str, Any], source: str = None):
        # Grype structure: {"matches": [{"vulnerability": {...}, "artifact": {...}}]}
        for match in result.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            
            # ID Normalization: Prefer CVE if available in aliases
            vuln_id = vuln.get("id")
            aliases = [r.get("id") for r in vuln.get("relatedVulnerabilities", []) if r.get("id")]
            
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

            self._add_finding(Finding(
                id=vuln_id,
                type=FindingType.VULNERABILITY,
                severity=Severity(vuln.get("severity", "UNKNOWN").upper()),
                component=artifact.get("name"),
                version=artifact.get("version"),
                description=vuln.get("description", ""),
                scanners=["grype"],
                details={
                    "fixed_version": ", ".join(vuln.get("fix", {}).get("versions", [])),
                    "datasource": vuln.get("dataSource"),
                    "urls": vuln.get("urls", []),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "namespace": vuln.get("namespace")
                },
                aliases=aliases
            ), source=source)

    def _normalize_osv(self, result: Dict[str, Any], source: str = None):
        # OSV structure: {"osv_vulnerabilities": [{"component":..., "vulnerabilities": [...]}]}
        for item in result.get("osv_vulnerabilities", []):
            comp_name = item.get("component")
            comp_version = item.get("version")
            
            for vuln in item.get("vulnerabilities", []):
                # 1. Determine Severity
                severity = "UNKNOWN"
                
                # Check database_specific (common in GHSA)
                if "database_specific" in vuln and "severity" in vuln["database_specific"]:
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
                                if fixed_version: break
                        if fixed_version: break

                # 3. ID Normalization: Prefer CVE if available in aliases
                vuln_id = vuln.get("id")
                aliases = vuln.get("aliases", [])
                
                # Handle prefixed CVEs like DEBIAN-CVE-2025-10148
                if vuln_id and "CVE-" in vuln_id and not vuln_id.startswith("CVE-"):
                    # Try to extract CVE
                    match = re.search(r'(CVE-\d{4}-\d{4,})', vuln_id)
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
                
                self._add_finding(Finding(
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
                        "osv_url": f"https://osv.dev/vulnerability/{vuln.get('id')}"
                    },
                    aliases=aliases
                ), source=source)

    def _normalize_outdated(self, result: Dict[str, Any], source: str = None):
        for item in result.get("outdated_dependencies", []):
            self._add_finding(Finding(
                id=f"OUTDATED-{item['component']}",
                type=FindingType.OUTDATED,
                severity=Severity(item.get("severity", "INFO")),
                component=item.get("component"),
                version=item.get("current_version"),
                description=item.get("message"),
                scanners=["outdated_packages"],
                details={
                    "fixed_version": item.get("latest_version")
                }
            ), source=source)

    def _normalize_license(self, result: Dict[str, Any], source: str = None):
        for item in result.get("license_issues", []):
            self._add_finding(Finding(
                id=f"LIC-{item['license']}",
                type=FindingType.LICENSE,
                severity=Severity(item.get("severity", "MEDIUM")), # Mapped WARNING to MEDIUM
                component=item.get("component"),
                version=item.get("version"),
                description=item.get("message"),
                scanners=["license_compliance"],
                details={"license": item.get("license")}
            ), source=source)

    def _normalize_scorecard(self, result: Dict[str, Any], source: str = None):
        for item in result.get("scorecard_issues", []):
            scorecard = item.get("scorecard", {})
            overall = scorecard.get("overallScore", 0)
            
            # Extract failed checks
            failed_checks = []
            for check in scorecard.get("checks", []):
                if check.get("score", 10) < 5:
                    failed_checks.append(f"{check.get('name')}: {check.get('score')}/10")
            
            details_text = ", ".join(failed_checks[:3])
            if len(failed_checks) > 3:
                details_text += "..."
                
            description = f"Low OpenSSF Scorecard score: {overall}/10. Issues: {details_text}" if failed_checks else item.get("warning")

            self._add_finding(Finding(
                id=f"SCORE-{item['component']}",
                type=FindingType.OTHER, # Quality not in enum yet
                severity=Severity.MEDIUM, 
                component=item.get("component"),
                version=item.get("version"),
                description=description,
                scanners=["deps_dev"],
                details={
                    "scorecard": scorecard,
                    "overall_score": overall,
                    "failed_checks": failed_checks
                }
            ), source=source)

    def _normalize_malware(self, result: Dict[str, Any], source: str = None):
        for item in result.get("malware_issues", []):
            malware_info = item.get("malware_info", {})
            threats = malware_info.get("threats", [])
            
            description = "Potential malware detected"
            if threats:
                description = f"Malware detected: {', '.join(threats)}"
            elif malware_info.get("description"):
                description = f"Malware detected: {malware_info.get('description')}"

            self._add_finding(Finding(
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
                    "reference": malware_info.get("reference")
                }
            ), source=source)

    def _normalize_eol(self, result: Dict[str, Any], source: str = None):
        for item in result.get("eol_issues", []):
            eol_info = item.get("eol_info", {})
            eol_date = eol_info.get("eol")
            cycle = eol_info.get("cycle")
            latest = eol_info.get("latest")
            
            self._add_finding(Finding(
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
                    "lts": eol_info.get("lts")
                }
            ), source=source)

    def _normalize_typosquatting(self, result: Dict[str, Any], source: str = None):
        for item in result.get("typosquatting_issues", []):
            similarity = item.get("similarity", 0)
            imitated = item.get("imitated_package")
            
            self._add_finding(Finding(
                id=f"TYPO-{item['component']}",
                type=FindingType.MALWARE, # Typosquatting is a form of malware/attack
                severity=Severity.CRITICAL, 
                component=item.get("component"),
                version=item.get("version"),
                description=f"Possible typosquatting detected! '{item.get('component')}' is {similarity*100:.1f}% similar to popular package '{imitated}'",
                scanners=["typosquatting"],
                details={
                    "imitated_package": imitated,
                    "similarity": similarity
                }
            ), source=source)

    def _normalize_opengrep(self, result: Dict[str, Any], source: str = None):
        # OpenGrep structure: {"findings": [OpenGrepFinding objects]}
        for finding in result.get("findings", []):
            # finding is a dict
            check_id = finding.get("check_id", "unknown-check")
            path = finding.get("path", "unknown")
            extra = finding.get("extra", {})
            
            severity_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW"
            }
            
            severity = severity_map.get(extra.get("severity"), "MEDIUM")
            message = extra.get("message", "No description provided")
            
            # Create unique ID
            finding_hash = hashlib.md5(f"{check_id}:{path}:{message}".encode()).hexdigest()
            finding_id = f"SAST-{finding_hash[:8]}"
            
            self._add_finding(Finding(
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
                    "metadata": extra.get("metadata")
                }
            ), source=source)

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
                
                self._add_finding(Finding(
                    id=query_id,
                    type=FindingType.IAC, # Using IAC for KICS
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
                        "actual_value": file_obj.get("actual_value")
                    }
                ), source=source)

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
            finding_hash = hashlib.md5(f"{rule_id}:{file_path}:{line}".encode()).hexdigest()
            finding_id = f"BEARER-{finding_hash[:8]}"
            
            self._add_finding(Finding(
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
                    "documentation": f.get("documentation_url")
                }
            ), source=source)

