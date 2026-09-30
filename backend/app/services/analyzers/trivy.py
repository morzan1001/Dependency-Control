import logging

from app.core.config import settings
from app.schemas.sbom import SBOMFormat

from .cli_base import CLIAnalyzer, run_process

logger = logging.getLogger(__name__)


class TrivyAnalyzer(CLIAnalyzer):
    name = "trivy"
    cli_command = "trivy"
    empty_result_key = "Results"

    # Retry transient Trivy server errors (e.g. layer cache miss after a DB update).
    max_retries = 3
    retry_delay = 3.0
    # Format conversion reads one file and writes one file, so a syft that is still going after
    # this is stuck rather than busy, and Trivy reads the original format well enough to continue.
    syft_convert_timeout = 120

    retryable_patterns = (
        *CLIAnalyzer.retryable_patterns,
        "layer cache missing",
        "failed to apply layers",
        "unavailable",
    )

    def _build_command_args(self, sbom_path: str) -> list[str]:
        """Build Trivy CLI command arguments; adds --server when TRIVY_SERVER_URL is set."""
        args = [
            "trivy",
            "sbom",
            "--format",
            "json",
            "--quiet",
        ]

        if settings.TRIVY_SERVER_URL:
            args.extend(["--server", settings.TRIVY_SERVER_URL])

        args.append(sbom_path)
        return args

    async def _preprocess_sbom(self, sbom_path: str, sbom_format: SBOMFormat) -> tuple[str, list[str]]:
        """Convert to CycloneDX via syft when the SBOM isn't already CycloneDX or SPDX (both native to Trivy)."""
        if sbom_format in (SBOMFormat.CYCLONEDX, SBOMFormat.SPDX):
            return sbom_path, []

        logger.info("SBOM format not natively supported by Trivy (likely Syft JSON). Attempting conversion...")
        # Listed even when syft fails: a timed-out syft can leave a partial file behind.
        converted_sbom_path = sbom_path + ".cdx.json"

        result = await run_process(
            ["syft", "convert", sbom_path, "-o", f"cyclonedx-json={converted_sbom_path}"], self.syft_convert_timeout
        )
        if result is None:
            logger.warning(
                "Syft conversion did not finish within %ss. Proceeding with original file.",
                self.syft_convert_timeout,
            )
            return sbom_path, [converted_sbom_path]
        _, stderr, returncode = result

        if returncode == 0:
            logger.info("Successfully converted SBOM to CycloneDX for Trivy.")
            return converted_sbom_path, [converted_sbom_path]

        logger.warning(f"Syft conversion failed: {stderr.decode()}. Proceeding with original file.")
        return sbom_path, [converted_sbom_path]
