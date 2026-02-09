import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.models.finding import Severity

from .cli_base import CLIAnalyzer

logger = logging.getLogger(__name__)


class TrivyAnalyzer(CLIAnalyzer):
    name = "trivy"
    cli_command = "trivy"
    empty_result_key = "Results"

    def _build_command_args(self, sbom_path: str, settings: Optional[Dict[str, Any]]) -> List[str]:
        """Build Trivy command arguments."""
        return [
            "trivy",
            "sbom",
            "--format",
            "json",
            "--quiet",
            sbom_path,
        ]

    async def _preprocess_sbom(
        self,
        sbom: Dict[str, Any],
        tmp_sbom_path: str,
        settings: Optional[Dict[str, Any]],
    ) -> Tuple[str, List[str]]:
        """
        Convert SBOM to CycloneDX if needed.

        Trivy supports CycloneDX and SPDX formats natively.
        For other formats (like Syft JSON), we convert using syft.
        """
        is_cyclonedx = "bomFormat" in sbom and sbom["bomFormat"] == "CycloneDX"
        is_spdx = "spdxVersion" in sbom

        if is_cyclonedx or is_spdx:
            return tmp_sbom_path, []

        # Attempt to convert using Syft
        logger.info("SBOM format not natively supported by Trivy (likely Syft JSON). Attempting conversion...")
        converted_sbom_path = tmp_sbom_path + ".cdx.json"

        convert_process = await asyncio.create_subprocess_exec(
            "syft",
            "convert",
            tmp_sbom_path,
            "-o",
            "cyclonedx-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await convert_process.communicate()

        if convert_process.returncode == 0:
            # Write the converted output to file
            with open(converted_sbom_path, "wb") as f:
                f.write(stdout)
            logger.info("Successfully converted SBOM to CycloneDX for Trivy.")
            return converted_sbom_path, [converted_sbom_path]

        logger.warning(f"Syft conversion failed: {stderr.decode()}. Proceeding with original file.")
        return tmp_sbom_path, []

    def _parse_output(self, stdout: bytes) -> Dict[str, Any]:
        """Parse Trivy JSON output and normalize vulnerabilities."""
        try:
            output_str = stdout.decode()
            if not output_str.strip():
                return {self.empty_result_key: [], "trivy_vulnerabilities": []}

            data = json.loads(output_str)
            normalized_vulns = self._normalize_vulnerabilities(data)

            return {
                **data,
                "trivy_vulnerabilities": normalized_vulns,
            }
        except json.JSONDecodeError:
            output_str = stdout.decode()
            return {
                "error": f"Invalid JSON output from {self.name}",
                "output": output_str,
            }

    def _normalize_vulnerabilities(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Trivy vulnerabilities with consistent severity and message."""
        normalized = []
        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            vulns = result.get("Vulnerabilities", [])

            for vuln in vulns:
                severity = self._map_severity(vuln.get("Severity", "UNKNOWN"))
                vuln_id = vuln.get("VulnerabilityID", "")
                pkg_name = vuln.get("PkgName", "")
                installed_version = vuln.get("InstalledVersion", "")
                fixed_version = vuln.get("FixedVersion", "")
                title = vuln.get("Title", "")

                message = self._create_message(vuln_id, pkg_name, installed_version, fixed_version, title)

                normalized.append(
                    {
                        "id": vuln_id,
                        "component": pkg_name,
                        "version": installed_version,
                        "fixed_version": fixed_version,
                        "severity": severity,
                        "message": message,
                        "target": target,
                        "title": title,
                        "description": vuln.get("Description", ""),
                        "references": vuln.get("References", []),
                        "cvss": vuln.get("CVSS", {}),
                    }
                )

        return normalized

    def _map_severity(self, trivy_severity: str) -> str:
        """Map Trivy severity to our Severity enum."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL.value,
            "HIGH": Severity.HIGH.value,
            "MEDIUM": Severity.MEDIUM.value,
            "LOW": Severity.LOW.value,
            "UNKNOWN": Severity.INFO.value,
        }
        return severity_map.get(trivy_severity.upper(), Severity.MEDIUM.value)

    def _create_message(
        self,
        vuln_id: str,
        pkg_name: str,
        installed_version: str,
        fixed_version: str,
        title: str,
    ) -> str:
        """Create a human-readable message for the vulnerability."""
        if title:
            msg = f"{vuln_id}: {title}"
        else:
            msg = f"{vuln_id} in {pkg_name}@{installed_version}"

        if fixed_version:
            msg += f" (fix available: {fixed_version})"

        return msg
