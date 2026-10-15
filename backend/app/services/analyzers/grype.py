from typing import Any

from .cli_base import CLIAnalyzer

# normalize_grype reads nothing else; matchDetails and the top-level descriptor, source and distro only add size.
_READ_MATCH_KEYS = ("vulnerability", "artifact", "relatedVulnerabilities")


class GrypeAnalyzer(CLIAnalyzer):
    name = "grype"
    cli_command = "grype"
    empty_result_key = "matches"

    # Grype's shared vuln DB briefly disappears during its refresh CronJob; a retry almost always succeeds.
    max_retries = 3
    retry_delay = 3.0
    # Large Java SBOMs can exceed the 5-min default.
    cli_timeout = 600

    retryable_patterns = (
        *CLIAnalyzer.retryable_patterns,
        "database does not exist",
        "failed to update vulnerability database",
        "database integrity check failed",
        "no such file or directory",  # grype-db filesystem race during sweep
    )
    # Empty stderr on a non-zero exit means grype was killed (signal/OOM) before reporting.
    retry_on_empty_stderr = True

    def _parse_output(self, stdout: bytes) -> dict[str, Any]:
        parsed = super()._parse_output(stdout)
        if "error" in parsed:
            return parsed
        return {"matches": [{key: m[key] for key in _READ_MATCH_KEYS if key in m} for m in parsed.get("matches") or []]}

    def _build_command_args(self, sbom_path: str) -> list[str]:
        """No --quiet: it hides the stderr _is_retryable_error inspects, so transient DB failures would never retry."""
        return [
            "grype",
            f"sbom:{sbom_path}",
            "-o",
            "json",
        ]
