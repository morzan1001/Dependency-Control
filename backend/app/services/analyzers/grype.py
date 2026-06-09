import json
from typing import Any, Dict, List, Optional

from app.models.finding import Severity

from .cli_base import CLIAnalyzer


class GrypeAnalyzer(CLIAnalyzer):
    name = "grype"
    cli_command = "grype"
    empty_result_key = "matches"

    # Grype reads its ~1.8 GB vulnerability DB from a shared, read-only GCSFuse
    # mount (GRYPE_DB_SHARED=true) that the grype-db-updater CronJob refreshes
    # periodically. During that refresh window — and on occasional transient
    # GCSFuse read glitches — grype exits non-zero with "failed to load
    # vulnerability db: database does not exist" even though the rest of the
    # pipeline (trivy via its remote server, osv) runs cleanly. A quick retry
    # almost always succeeds, so mirror trivy's retry policy.
    max_retries = 3
    retry_delay = 3.0
    # Large Java SBOMs (~600+ deps) can legitimately need more than the 5-min
    # CLIAnalyzer default; the successful baseline scans on the affected project
    # ran up to ~10 min, so cap at 600 s before declaring the run dead.
    cli_timeout = 600

    _RETRYABLE_PATTERNS = (
        "database does not exist",
        "failed to update vulnerability database",
        "database integrity check failed",
        "no such file or directory",  # grype-db filesystem race during sweep
        "context deadline exceeded",
        "connection refused",
        "connection reset",
        "i/o timeout",
        "eof",
        "timed out after",  # the cli_base timeout wrapper's own stderr string
    )

    def _is_retryable_error(self, stderr: bytes) -> bool:
        msg = stderr.decode(errors="replace").strip().lower()
        # A non-zero exit with empty stderr means grype was killed before it
        # could report anything (signal/OOM) or had its output otherwise
        # swallowed. Both are transient, so retry instead of surfacing an
        # empty SCAN-ERROR-grype finding.
        if not msg:
            return True
        return any(p in msg for p in self._RETRYABLE_PATTERNS)

    def _build_command_args(self, sbom_path: str, settings: Optional[Dict[str, Any]]) -> List[str]:
        """Build Grype command arguments.

        The Grype DB path is controlled via GRYPE_DB_CACHE_DIR environment variable,
        which is set in docker-entrypoint.sh or by the Kubernetes volume mount.
        No need to set it here - the CLI reads it from the environment.

        ``--quiet`` is intentionally NOT passed: it suppresses grype's stderr,
        including the fatal "failed to load vulnerability db" message that
        ``_is_retryable_error`` inspects to decide whether a transient failure
        is retryable. With ``--quiet`` the stderr arrives empty, the retry never
        fires, and the failure surfaces as an empty SCAN-ERROR-grype finding.
        The JSON report goes to stdout regardless, so omitting it is safe.
        """
        return [
            "grype",
            f"sbom:{sbom_path}",
            "-o",
            "json",
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
