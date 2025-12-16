from typing import List, Dict, Any
import hashlib
import re
from app.models.finding import Finding, Severity, FindingType

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
        Returns the list of deduplicated findings.
        """
        return list(self.findings.values())

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
            
            self._add_finding(Finding(
                id=finding_id,
                type=FindingType.SECRET,
                severity=Severity.CRITICAL,
                component=file_path,
                version="", # No version for secrets in files
                description=f"Secret detected: {detector}",
                scanners=["trufflehog"],
                details={
                    "detector": detector,
                    "decoder": finding.get("DecoderName"),
                    "verified": finding.get("Verified"),
                    # Do NOT store Raw secret in details unless encrypted/redacted. 
                    # TruffleHog provides "Redacted" field.
                    "redacted": finding.get("Redacted")
                }
            ), source=source)

    def _add_finding(self, finding: Finding, source: str = None):
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
        
        # 3. Fallback to primary key check (legacy/safety)
        if not existing_key and primary_key in self.findings:
            existing_key = primary_key

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

                self._add_finding(Finding(
                    id=vuln_id,
                    type=FindingType.VULNERABILITY,
                    severity=Severity(vuln.get("Severity", "UNKNOWN").upper()),
                    component=vuln.get("PkgName"),
                    version=vuln.get("InstalledVersion"),
                    description=vuln.get("Title") or vuln.get("Description", ""),
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

