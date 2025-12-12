from typing import List, Dict, Any
import hashlib

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
        self.findings: Dict[str, Dict[str, Any]] = {}

    def aggregate(self, analyzer_name: str, result: Dict[str, Any]):
        """
        Dispatches the result to the specific normalizer based on analyzer name.
        """
        if not result:
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
            normalizers[analyzer_name](result)

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Returns the list of deduplicated findings.
        """
        return list(self.findings.values())

    def _normalize_trufflehog(self, result: Dict[str, Any]):
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
            
            self._add_finding({
                "id": finding_id,
                "type": "secret",
                "severity": "CRITICAL",
                "component": file_path,
                "version": "", # No version for secrets in files
                "description": f"Secret detected: {detector}",
                "scanners": ["trufflehog"],
                "details": {
                    "detector": detector,
                    "decoder": finding.get("DecoderName"),
                    "verified": finding.get("Verified"),
                    # Do NOT store Raw secret in details unless encrypted/redacted. 
                    # TruffleHog provides "Redacted" field.
                    "redacted": finding.get("Redacted")
                }
            })

    def _add_finding(self, finding: Dict[str, Any]):
        """
        Adds a finding to the map, merging if it already exists.
        Key for deduplication: type + id + component + version
        """
        # ID normalization (e.g. preferring CVE over GHSA) is handled in specific normalizers.
        
        key = f"{finding['type']}:{finding['id']}:{finding['component']}:{finding['version']}"
        
        if key in self.findings:
            existing = self.findings[key]
            
            # 1. Merge scanners list
            existing["scanners"] = list(set(existing["scanners"] + finding["scanners"]))
            
            # 2. Merge Severity (keep highest)
            existing_severity_val = SEVERITY_ORDER.get(existing["severity"], 0)
            new_severity_val = SEVERITY_ORDER.get(finding["severity"], 0)
            
            if new_severity_val > existing_severity_val:
                existing["severity"] = finding["severity"]
                
            # 3. Merge Details
            if "details" in finding:
                existing["details"].update(finding["details"])
                
            # 4. Merge Aliases (if any)
            if "aliases" in finding:
                existing_aliases = existing.get("aliases", [])
                existing["aliases"] = list(set(existing_aliases + finding.get("aliases", [])))
                
        else:
            self.findings[key] = finding

    def _normalize_trivy(self, result: Dict[str, Any]):
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
                
                # CVSS Parsing
                cvss_score = None
                cvss_vector = None
                if "CVSS" in vuln:
                    # Trivy CVSS structure varies, usually {"nvd": {"V3Score": ...}, "redhat": ...}
                    # We prefer NVD V3, then V2, then Vendor
                    for source in ["nvd", "redhat", "ghsa", "bitnami"]:
                        if source in vuln["CVSS"]:
                            data = vuln["CVSS"][source]
                            if "V3Score" in data:
                                cvss_score = data["V3Score"]
                                cvss_vector = data.get("V3Vector")
                                break
                            elif "V2Score" in data and cvss_score is None:
                                cvss_score = data["V2Score"]
                                cvss_vector = data.get("V2Vector")

                self._add_finding({
                    "id": vuln.get("VulnerabilityID"),
                    "type": "vulnerability",
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "component": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "description": vuln.get("Title") or vuln.get("Description", ""),
                    "fixed_version": vuln.get("FixedVersion"),
                    "scanners": ["trivy"],
                    "details": {
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "references": references,
                        "published_date": published_date,
                        "last_modified_date": last_modified_date,
                        "cwe_ids": cwe_ids,
                        "layer_id": vuln.get("Layer", {}).get("Digest")
                    },
                    "aliases": [] 
                })

    def _normalize_grype(self, result: Dict[str, Any]):
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

            self._add_finding({
                "id": vuln_id,
                "type": "vulnerability",
                "severity": vuln.get("severity", "UNKNOWN").upper(),
                "component": artifact.get("name"),
                "version": artifact.get("version"),
                "description": vuln.get("description", ""),
                "fixed_version": ", ".join(vuln.get("fix", {}).get("versions", [])),
                "scanners": ["grype"],
                "details": {
                    "datasource": vuln.get("dataSource"),
                    "urls": vuln.get("urls", []),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "namespace": vuln.get("namespace")
                },
                "aliases": aliases
            })

    def _normalize_osv(self, result: Dict[str, Any]):
        # OSV structure: {"osv_vulnerabilities": [{"component":..., "vulnerabilities": [...]}]}
        for item in result.get("osv_vulnerabilities", []):
            comp_name = item.get("component")
            comp_version = item.get("version")
            
            for vuln in item.get("vulnerabilities", []):
                # OSV severity is often CVSS vector, mapping might be required. 
                # For simplicity, let's default to UNKNOWN or parse if available.
                severity = "UNKNOWN"
                # Try to extract severity from database_specific or ecosystem_specific
                if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                     severity = vuln["database_specific"]["severity"].upper()
                
                # ID Normalization: Prefer CVE if available in aliases
                vuln_id = vuln.get("id")
                aliases = vuln.get("aliases", [])
                
                # If current ID is GHSA/GO/etc and a CVE exists in aliases, use CVE as primary ID
                # This helps deduplicate with Trivy/Grype which usually report CVEs
                cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
                if cve_alias and not vuln_id.startswith("CVE-"):
                    # Add original ID to aliases list to preserve it
                    if vuln_id not in aliases:
                        aliases.append(vuln_id)
                    vuln_id = cve_alias
                
                self._add_finding({
                    "id": vuln_id,
                    "type": "vulnerability",
                    "severity": severity, 
                    "component": comp_name,
                    "version": comp_version,
                    "description": vuln.get("summary") or vuln.get("details", ""),
                    "scanners": ["osv"],
                    "details": {"references": vuln.get("references")},
                    "aliases": aliases
                })

    def _normalize_outdated(self, result: Dict[str, Any]):
        for item in result.get("outdated_dependencies", []):
            self._add_finding({
                "id": f"OUTDATED-{item['component']}",
                "type": "outdated",
                "severity": item.get("severity", "INFO"),
                "component": item.get("component"),
                "version": item.get("current_version"),
                "description": item.get("message"),
                "fixed_version": item.get("latest_version"),
                "scanners": ["outdated_packages"],
                "details": {}
            })

    def _normalize_license(self, result: Dict[str, Any]):
        for item in result.get("license_issues", []):
            self._add_finding({
                "id": f"LIC-{item['license']}",
                "type": "license",
                "severity": item.get("severity", "WARNING"),
                "component": item.get("component"),
                "version": item.get("version"),
                "description": item.get("message"),
                "scanners": ["license_compliance"],
                "details": {"license": item.get("license")}
            })

    def _normalize_scorecard(self, result: Dict[str, Any]):
        for item in result.get("scorecard_issues", []):
            self._add_finding({
                "id": f"SCORE-{item['component']}",
                "type": "quality",
                "severity": "MEDIUM", # Default for low scorecard
                "component": item.get("component"),
                "version": item.get("version"),
                "description": item.get("warning"),
                "scanners": ["deps_dev"],
                "details": {"scorecard": item.get("scorecard")}
            })

    def _normalize_malware(self, result: Dict[str, Any]):
        for item in result.get("malware_issues", []):
            self._add_finding({
                "id": f"MALWARE-{item['component']}",
                "type": "malware",
                "severity": "CRITICAL",
                "component": item.get("component"),
                "version": item.get("version"),
                "description": "Potential malware detected",
                "scanners": ["os_malware"],
                "details": {"info": item.get("malware_info")}
            })

    def _normalize_eol(self, result: Dict[str, Any]):
        for item in result.get("eol_issues", []):
            self._add_finding({
                "id": f"EOL-{item['component']}",
                "type": "eol",
                "severity": "HIGH",
                "component": item.get("component"),
                "version": item.get("version"),
                "description": f"End of Life reached on {item.get('eol_date')}",
                "scanners": ["end_of_life"],
                "details": {"eol_date": item.get("eol_date"), "cycle": item.get("cycle")}
            })

    def _normalize_typosquatting(self, result: Dict[str, Any]):
        for item in result.get("typosquatting_issues", []):
            self._add_finding({
                "id": f"TYPO-{item['component']}",
                "type": "typosquatting",
                "severity": "CRITICAL", # Typosquatting is usually malicious
                "component": item.get("component"),
                "version": item.get("version"),
                "description": f"Possible typosquatting detected! Looks like '{item.get('imitated_package')}'",
                "scanners": ["typosquatting"],
                "details": {
                    "imitated_package": item.get("imitated_package"),
                    "similarity": item.get("similarity")
                }
            })

    def _normalize_opengrep(self, result: Dict[str, Any]):
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
            
            self._add_finding({
                "id": finding_id,
                "type": "sast",
                "severity": severity,
                "component": path,
                "version": "",
                "description": message,
                "scanners": ["opengrep"],
                "details": {
                    "check_id": check_id,
                    "start": finding.get("start"),
                    "end": finding.get("end"),
                    "metadata": extra.get("metadata")
                }
            })

    def _normalize_kics(self, result: Dict[str, Any]):
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
                
                self._add_finding({
                    "id": query_id,
                    "type": "sast", # Using sast for IaC/Misconfiguration to align with Security category
                    "severity": severity,
                    "component": file_name,
                    "version": "",
                    "description": f"{query_name}: {description}",
                    "scanners": ["kics"],
                    "details": {
                        "category": category,
                        "platform": query.get("platform"),
                        "line": line,
                        "issue_type": file_obj.get("issue_type"),
                        "expected_value": file_obj.get("expected_value"),
                        "actual_value": file_obj.get("actual_value")
                    }
                })

    def _normalize_bearer(self, result: Dict[str, Any]):
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
            
            self._add_finding({
                "id": finding_id,
                "type": "sast",
                "severity": severity,
                "component": file_path,
                "version": "",
                "description": message,
                "scanners": ["bearer"],
                "details": {
                    "rule_id": rule_id,
                    "line": line,
                    "cwe_ids": f.get("cwe_ids", []),
                    "documentation": f.get("documentation_url")
                }
            })

