import asyncio
import logging
from pathlib import Path
from typing import Any

from app.core.config import settings

from .cli_base import CLIAnalyzer, kill_and_reap

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

    _RETRYABLE_PATTERNS = (
        "layer cache missing",
        "failed to apply layers",
        "connection refused",
        "connection reset",
        "eof",
        "context deadline exceeded",
        "unavailable",
        "i/o timeout",
    )

    def _is_retryable_error(self, stderr: bytes) -> bool:
        msg = stderr.decode(errors="replace").lower()
        return any(p in msg for p in self._RETRYABLE_PATTERNS)

    def _build_command_args(self, sbom_path: str, settings_dict: dict[str, Any] | None) -> list[str]:
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

    async def _preprocess_sbom(
        self,
        sbom: dict[str, Any],
        tmp_sbom_path: str,
        settings_dict: dict[str, Any] | None,
    ) -> tuple[str, list[str]]:
        """Convert to CycloneDX via syft when the SBOM isn't already CycloneDX or SPDX (both native to Trivy)."""
        is_cyclonedx = "bomFormat" in sbom and sbom["bomFormat"] == "CycloneDX"
        is_spdx = "spdxVersion" in sbom

        if is_cyclonedx or is_spdx:
            return tmp_sbom_path, []

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
        try:
            stdout, stderr = await asyncio.wait_for(convert_process.communicate(), timeout=self.syft_convert_timeout)
        except asyncio.TimeoutError:
            await kill_and_reap(convert_process)
            logger.warning(
                "Syft conversion did not finish within %ss. Proceeding with original file.",
                self.syft_convert_timeout,
            )
            return tmp_sbom_path, []
        except asyncio.CancelledError:
            await kill_and_reap(convert_process)
            raise

        if convert_process.returncode == 0:
            await asyncio.to_thread(Path(converted_sbom_path).write_bytes, stdout)
            logger.info("Successfully converted SBOM to CycloneDX for Trivy.")
            return converted_sbom_path, [converted_sbom_path]

        logger.warning(f"Syft conversion failed: {stderr.decode()}. Proceeding with original file.")
        return tmp_sbom_path, []
