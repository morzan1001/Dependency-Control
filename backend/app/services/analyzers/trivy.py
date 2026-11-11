import asyncio
import contextlib
import json
import logging
import mmap
import os
import re

from app.core.config import settings
from app.schemas.sbom import SBOMFormat

from .cli_base import CLIAnalyzer, run_process

logger = logging.getLogger(__name__)

_RHEL_NAME = re.compile(rb'"name"\s*:\s*"rhel"')


# Trivy's OS family is the operating-system component name verbatim; syft names Red Hat "rhel", Trivy "redhat".
def _name_rhel_redhat(source: str, target: str) -> bool:
    try:
        # Searched in place: SBOMs have no size limit, and almost none name a rhel component.
        with open(source, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if not _RHEL_NAME.search(data):
                return False
            bom = json.loads(data[:])
    except ValueError:
        return False
    components = bom.get("components") if isinstance(bom, dict) else None
    if not isinstance(components, list):
        return False
    rhel = [
        c for c in components if isinstance(c, dict) and c.get("type") == "operating-system" and c.get("name") == "rhel"
    ]
    if not rhel:
        return False
    for component in rhel:
        component["name"] = "redhat"
    try:
        with open(target, "w", encoding="utf-8") as out:
            json.dump(bom, out)
    except OSError as e:
        logger.warning("Trivy scans %s unrenamed, its copy could not be written: %s", source, e)
        with contextlib.suppress(OSError):
            os.remove(target)
        return False
    return True


async def _redhat_copy(path: str, cleanup: list[str]) -> tuple[str, list[str]]:
    # The other scanners read the posted file concurrently, and a failed rewrite must not spoil a converted one.
    redhat_path = path + ".redhat.json"
    if await asyncio.to_thread(_name_rhel_redhat, path, redhat_path):
        return redhat_path, [*cleanup, redhat_path]
    return path, cleanup


class TrivyAnalyzer(CLIAnalyzer):
    name = "trivy"
    cli_command = "trivy"
    empty_result_key = "Results"

    # Retry transient Trivy server errors (e.g. layer cache miss after a DB update).
    max_retries = 3
    retry_delay = 3.0
    # A syft conversion still running after this is stuck, and Trivy reads the original format well enough.
    syft_convert_timeout = 120

    retryable_patterns = (
        *CLIAnalyzer.retryable_patterns,
        "layer cache missing",
        "failed to apply layers",
        "unavailable",
    )

    def _build_command_args(self, sbom_path: str) -> list[str]:
        args = [
            "trivy",
            "sbom",
            "--format",
            "json",
            "--quiet",
            # Past cli_timeout, so a slow scan ends on the wrapper's non-retryable timeout, not trivy's retryable one.
            "--timeout",
            f"{self.cli_timeout + 60}s",
        ]

        if settings.TRIVY_SERVER_URL:
            args.extend(["--server", settings.TRIVY_SERVER_URL])

        args.append(sbom_path)
        return args

    async def _preprocess_sbom(self, sbom_path: str, sbom_format: SBOMFormat) -> tuple[str, list[str]]:
        """CycloneDX and SPDX are native to Trivy; other formats go through syft first."""
        if sbom_format == SBOMFormat.SPDX:
            return sbom_path, []
        if sbom_format == SBOMFormat.CYCLONEDX:
            return await _redhat_copy(sbom_path, [])

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
            return await _redhat_copy(converted_sbom_path, [converted_sbom_path])

        logger.warning(f"Syft conversion failed: {stderr.decode()}. Proceeding with original file.")
        return sbom_path, [converted_sbom_path]
