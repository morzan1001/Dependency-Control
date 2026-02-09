import json
from typing import Any, Dict, List, Optional

from app.models.finding import Severity

from .cli_base import CLIAnalyzer


class GrypeAnalyzer(CLIAnalyzer):
    name = "grype"
    cli_command = "grype"
    empty_result_key = "matches"

    def _build_command_args(self, sbom_path: str, settings: Optional[Dict[str, Any]]) -> List[str]:
        """Build Grype command arguments."""
        return [
            "grype",
            f"sbom:{sbom_path}",
            "-o",
            "json",
            "--quiet",
        ]

    def _parse_output(self, stdout: bytes) -> Dict[str, Any]:
        """Parse Grype JSON output and normalize vulnerabilities."""
        try:
            output_str = stdout.decode()
            if not output_str.strip():
                return {self.empty_result_key: [], "grype_vulnerabilities": []}

            data = json.loads(output_str)
            normalized_vulns = self._normalize_vulnerabilities(data)

            return {
                **data,
                "grype_vulnerabilities": normalized_vulns,
            }
        except json.JSONDecodeError:
            output_str = stdout.decode()
            return {
                "error": f"Invalid JSON output from {self.name}",
                "output": output_str,
            }

    def _normalize_vulnerabilities(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Grype matches with consistent severity and message."""
        normalized = []
        matches = data.get("matches", [])

        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            related_vulns = match.get("relatedVulnerabilities", [])

            severity = self._map_severity(vuln.get("severity", "Unknown"))
            vuln_id = vuln.get("id", "")
            pkg_name = artifact.get("name", "")
            installed_version = artifact.get("version", "")
            fixed_versions = vuln.get("fix", {}).get("versions", [])
            fixed_version = ""
            if isinstance(fixed_versions, list) and fixed_versions:
                fixed_version = str(fixed_versions[0]) if fixed_versions[0] else ""
            description = vuln.get("description", "")

            message = self._create_message(vuln_id, pkg_name, installed_version, fixed_version, description)

            normalized.append(
                {
                    "id": vuln_id,
                    "component": pkg_name,
                    "version": installed_version,
                    "fixed_version": fixed_version,
                    "severity": severity,
                    "message": message,
                    "description": description,
                    "data_source": vuln.get("dataSource", ""),
                    "urls": vuln.get("urls", []),
                    "cvss": vuln.get("cvss", []),
                    "related_vulnerabilities": [rv.get("id") for rv in related_vulns if rv.get("id")],
                    "artifact_type": artifact.get("type", ""),
                    "artifact_purl": artifact.get("purl", ""),
                }
            )

        return normalized

    def _map_severity(self, grype_severity: str) -> str:
        """Map Grype severity to our Severity enum."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL.value,
            "HIGH": Severity.HIGH.value,
            "MEDIUM": Severity.MEDIUM.value,
            "LOW": Severity.LOW.value,
            "NEGLIGIBLE": Severity.INFO.value,
            "UNKNOWN": Severity.INFO.value,
        }
        return severity_map.get(grype_severity.upper(), Severity.MEDIUM.value)

    def _create_message(
        self,
        vuln_id: str,
        pkg_name: str,
        installed_version: str,
        fixed_version: str,
        description: str,
    ) -> str:
        """Create a human-readable message for the vulnerability."""
        # Use first sentence of description if available
        if description:
            first_sentence = description.split(".")[0]
            if len(first_sentence) > 100:
                first_sentence = first_sentence[:97] + "..."
            msg = f"{vuln_id}: {first_sentence}"
        else:
            msg = f"{vuln_id} in {pkg_name}@{installed_version}"

        if fixed_version:
            msg += f" (fix available: {fixed_version})"

        return msg
