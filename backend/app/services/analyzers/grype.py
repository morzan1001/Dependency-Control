from typing import Any

from .cli_base import CLIAnalyzer


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
        # Empty stderr on a non-zero exit means grype was killed (signal/OOM) before
        # reporting; treat as transient rather than surfacing an empty error finding.
        if not msg:
            return True
        return any(p in msg for p in self._RETRYABLE_PATTERNS)

    def _build_command_args(self, sbom_path: str, settings: dict[str, Any] | None) -> list[str]:
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
