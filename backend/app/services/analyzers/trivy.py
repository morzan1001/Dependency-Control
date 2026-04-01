import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.models.finding import Severity

from .cli_base import CLIAnalyzer

logger = logging.getLogger(__name__)


class TrivyAnalyzer(CLIAnalyzer):
    name = "trivy"
    cli_command = "trivy"
    empty_result_key = "Results"

    def _is_server_mode(self) -> bool:
        """Check if Trivy should use server mode (HTTP) instead of local CLI."""
        return bool(settings.TRIVY_SERVER_URL)

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings_dict: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run Trivy analysis - via server HTTP if configured, otherwise local CLI."""
        if self._is_server_mode():
            return await self._analyze_via_server(sbom)
        return await super().analyze(sbom, settings=settings_dict, parsed_components=parsed_components)

    async def _analyze_via_server(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Send SBOM to Trivy server for analysis via HTTP."""
        import httpx

        server_url = settings.TRIVY_SERVER_URL.rstrip("/")

        try:
            sbom_bytes = json.dumps(sbom).encode()

            async with httpx.AsyncClient(timeout=self.cli_timeout) as client:
                response = await client.post(
                    f"{server_url}/twirp/trivy.scanner.v1.Scanner/Scan",
                    content=sbom_bytes,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code != 200:
                    logger.error(f"Trivy server returned {response.status_code}: {response.text[:500]}")
                    return {"error": f"Trivy server error: HTTP {response.status_code}"}

                data = response.json()
                normalized_vulns = self._normalize_vulnerabilities(data)
                return {**data, "trivy_vulnerabilities": normalized_vulns}

        except httpx.TimeoutException:
            logger.error(f"Trivy server request timed out after {self.cli_timeout}s")
            return {"error": "Trivy server request timed out"}
        except httpx.ConnectError as e:
            logger.error(f"Cannot connect to Trivy server at {server_url}: {e}")
            return {"error": f"Cannot connect to Trivy server: {e}"}
        except Exception as e:
            logger.exception(f"Trivy server analysis failed: {e}")
            return {"error": f"Trivy server analysis failed: {e}"}

    def _build_command_args(self, sbom_path: str, settings_dict: Optional[Dict[str, Any]]) -> List[str]:
        """Build Trivy CLI command arguments (used in local/CLI mode)."""
        args = [
            "trivy",
            "sbom",
            "--format",
            "json",
            "--quiet",
        ]

        # If a remote server is configured but we're falling back to CLI,
        # still use the server to avoid needing a local DB
        if settings.TRIVY_SERVER_URL:
            args.extend(["--server", settings.TRIVY_SERVER_URL])

        args.append(sbom_path)
        return args

    async def _preprocess_sbom(
        self,
        sbom: Dict[str, Any],
        tmp_sbom_path: str,
        settings_dict: Optional[Dict[str, Any]],
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
            await asyncio.to_thread(Path(converted_sbom_path).write_bytes, stdout)
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
