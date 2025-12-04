from typing import List, Dict, Any
import hashlib

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

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Returns the list of deduplicated findings.
        """
        return list(self.findings.values())

    def _add_finding(self, finding: Dict[str, Any]):
        """
        Adds a finding to the map, merging if it already exists.
        Key for deduplication: type + id + component + version
        """
        key = f"{finding['type']}:{finding['id']}:{finding['component']}:{finding['version']}"
        
        if key in self.findings:
            existing = self.findings[key]
            # Merge scanners list
            existing["scanners"] = list(set(existing["scanners"] + finding["scanners"]))
            # Keep the higher severity if they differ (simple logic for now)
            # Ideally we'd have a severity ranking
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
                    "details": {"cvss": vuln.get("CVSS")}
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
                "details": {"datasource": vuln.get("dataSource")}
            })

    def _normalize_osv(self, result: Dict[str, Any]):
        # OSV structure: {"osv_vulnerabilities": [{"component":..., "vulnerabilities": [...]}]}
        for item in result.get("osv_vulnerabilities", []):
            comp_name = item.get("component")
            comp_version = item.get("version")
            
            for vuln in item.get("vulnerabilities", []):
                # OSV severity is often CVSS vector, we might need to map it. 
                # For simplicity, let's default to UNKNOWN or parse if available.
                # OSV JSON usually has "database_specific": {"severity": "..."} or similar
                severity = "UNKNOWN" 
                # Try to find severity in aliases or summary
                
                self._add_finding({
                    "id": vuln.get("id"),
                    "type": "vulnerability",
                    "severity": severity, 
                    "component": comp_name,
                    "version": comp_version,
                    "description": vuln.get("summary") or vuln.get("details", ""),
                    "scanners": ["osv"],
                    "details": {"references": vuln.get("references")}
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
