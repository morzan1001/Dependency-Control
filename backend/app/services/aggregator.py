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

        if analyzer_name == "trivy":
            self._normalize_trivy(result)
        elif analyzer_name == "grype":
            self._normalize_grype(result)
        elif analyzer_name == "osv":
            self._normalize_osv(result)
        elif analyzer_name == "outdated_packages":
            self._normalize_outdated(result)
        elif analyzer_name == "license_compliance":
            self._normalize_license(result)
        elif analyzer_name == "deps_dev":
            self._normalize_scorecard(result)
        elif analyzer_name == "os_malware":
            self._normalize_malware(result)

        elif analyzer_name == "end_of_life":
            self._normalize_eol(result)
            
        elif analyzer_name == "typosquatting":
            self._normalize_typosquatting(result)
            
        elif analyzer_name == "trufflehog":
            self._normalize_trufflehog(result)

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Returns the list of deduplicated findings.
        """
        return list(self.findings.values())

    def _normalize_trufflehog(self, result: Dict[str, Any]):
        # TruffleHog structure: {"findings": [TruffleHogFinding objects]}
        # We expect the result dict to contain a list of findings under "findings" key
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
            
            # Create a unique ID based on detector and file path (and maybe a hash of the secret if available safely)
            # We avoid storing the raw secret in the ID.
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
        # Normalize ID: If it's a GHSA/GO ID but we have a CVE alias, use CVE?
        # This logic is better handled in the specific normalizers (like OSV) before calling this.
        
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
                self._add_finding({
                    "id": vuln.get("VulnerabilityID"),
                    "type": "vulnerability",
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "component": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "description": vuln.get("Title") or vuln.get("Description", ""),
                    "fixed_version": vuln.get("FixedVersion"),
                    "scanners": ["trivy"],
                    "details": {"cvss": vuln.get("CVSS")},
                    "aliases": [] # Trivy doesn't always provide aliases in this structure easily
                })

    def _normalize_grype(self, result: Dict[str, Any]):
        # Grype structure: {"matches": [{"vulnerability": {...}, "artifact": {...}}]}
        for match in result.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            
            self._add_finding({
                "id": vuln.get("id"),
                "type": "vulnerability",
                "severity": vuln.get("severity", "UNKNOWN").upper(),
                "component": artifact.get("name"),
                "version": artifact.get("version"),
                "description": vuln.get("description", ""),
                "fixed_version": ", ".join(vuln.get("fix", {}).get("versions", [])),
                "scanners": ["grype"],
                "details": {"datasource": vuln.get("dataSource")},
                "aliases": vuln.get("relatedVulnerabilities", []) # Grype provides related IDs
            })

    def _normalize_osv(self, result: Dict[str, Any]):
        # OSV structure: {"osv_vulnerabilities": [{"component":..., "vulnerabilities": [...]}]}
        for item in result.get("osv_vulnerabilities", []):
            comp_name = item.get("component")
            comp_version = item.get("version")
            
            for vuln in item.get("vulnerabilities", []):
                # OSV severity is often CVSS vector, we might need to map it. 
                # For simplicity, let's default to UNKNOWN or parse if available.
                severity = "UNKNOWN"
                # Try to extract severity from database_specific or ecosystem_specific
                if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                     severity = vuln["database_specific"]["severity"].upper()
                
                # ID Normalization: Prefer CVE if available in aliases
                vuln_id = vuln.get("id")
                aliases = vuln.get("aliases", [])
                
                # If current ID is GHSA/GO/etc and we have a CVE in aliases, use CVE as primary ID
                # This helps deduplicate with Trivy/Grype which usually report CVEs
                cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
                if cve_alias and not vuln_id.startswith("CVE-"):
                    # Add original ID to aliases list so we don't lose it
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
