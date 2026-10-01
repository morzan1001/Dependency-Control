from typing import Any

from .cli_base import CLIAnalyzer

# normalize_grype reads nothing else; matchDetails and the top-level descriptor, source and distro only add size.
_READ_MATCH_KEYS = ("vulnerability", "artifact", "relatedVulnerabilities")


class GrypeAnalyzer(CLIAnalyzer):
    name = "grype"
    cli_command = "grype"
    empty_result_key = "matches"

    # Grype's shared read-only vuln DB can briefly disappear during its refresh CronJob;
    # such transient DB errors almost always succeed on retry.
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
        """Build Grype command arguments.

        Do not add ``--quiet``: it suppresses the stderr that ``_is_retryable_error``
        inspects, so transient DB failures would never be retried.
        """
        return [
            "grype",
            f"sbom:{sbom_path}",
            "-o",
            "json",
        ]
