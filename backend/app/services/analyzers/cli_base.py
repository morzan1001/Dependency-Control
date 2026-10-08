"""Shared base for analyzers that execute CLI tools (trivy, grype, etc.)."""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from abc import abstractmethod
from typing import Any

from app.schemas.sbom import SBOMFormat
from app.services.sbom_parser import sbom_parser

from .base import Analyzer

logger = logging.getLogger(__name__)

# docker-entrypoint.sh sweeps this prefix, since a killed pod leaves its copies on the /tmp emptyDir.
TEMP_SBOM_PREFIX = "dc-sbom-"


async def run_process(args: list[str], time_limit: float) -> tuple[bytes, bytes, int] | None:
    """Run a command to completion and return (stdout, stderr, returncode); None if it outlived ``time_limit``."""
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=time_limit)
    except asyncio.TimeoutError:
        return None
    finally:
        # Also on cancel, which takes the time limit with it; waiting reaps the child instead of leaving a zombie.
        if process.returncode is None:
            process.kill()
            await process.wait()
    return stdout, stderr, process.returncode or 0


class CLIAnalyzer(Analyzer):
    """Base class for analyzers that execute CLI tools with temp-file management and retry."""

    cli_command: str
    empty_result_key: str = "results"

    def is_tool_available(self) -> bool:
        """Check if the CLI tool is available in the system PATH."""
        return shutil.which(self.cli_command) is not None

    retryable_patterns: tuple[str, ...] = (
        "connection refused",
        "connection reset",
        "eof",
        "context deadline exceeded",
        "i/o timeout",
    )
    retry_on_empty_stderr = False

    def _is_retryable_error(self, stderr: bytes) -> bool:
        msg = stderr.decode(errors="replace").strip().lower()
        if not msg:
            return self.retry_on_empty_stderr
        return any(p in msg for p in self.retryable_patterns)

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Scan ``sbom`` from a temp file of its JSON."""
        sbom_path = await asyncio.to_thread(self._create_temp_sbom, sbom)
        try:
            return await self.analyze_file(sbom_path, sbom_parser.detect_format(sbom))
        finally:
            self._cleanup_files([sbom_path])

    async def analyze_file(self, sbom_path: str, sbom_format: SBOMFormat) -> dict[str, Any]:
        """Scan the SBOM file at ``sbom_path``, which stays the caller's, retrying transient failures."""
        if not self.is_tool_available():
            logger.warning(f"{self.name}: CLI tool '{self.cli_command}' not found in PATH")
            return {
                "error": f"CLI tool '{self.cli_command}' not found",
                "details": f"Please install {self.cli_command} and ensure it's in your PATH",
                self.empty_result_key: [],
            }

        extra_paths: list[str] = []
        try:
            target_path, extra_paths = await self._preprocess_sbom(sbom_path, sbom_format)
            args = self._build_command_args(target_path)

            attempt = 0
            while True:
                stdout, stderr, returncode = await self._execute_command(args)
                if returncode == 0:
                    return await asyncio.to_thread(self._parse_output, stdout)
                if attempt >= self.max_retries or not self._is_retryable_error(stderr):
                    return self._handle_error(stderr)
                delay = self.retry_delay * (2**attempt)
                logger.warning(
                    f"{self.name} failed (attempt {attempt + 1}/{1 + self.max_retries}), "
                    f"retrying in {delay:.1f}s: {stderr.decode()[:200]}"
                )
                await asyncio.sleep(delay)
                attempt += 1

        except Exception as e:
            logger.exception(f"Exception during {self.name} analysis")
            return {"error": f"Exception during {self.name} analysis: {e!s}"}

        finally:
            self._cleanup_files(extra_paths)

    def _create_temp_sbom(self, sbom: dict[str, Any]) -> str:
        """Create a temporary file containing the SBOM JSON."""
        with tempfile.NamedTemporaryFile(mode="w+", prefix=TEMP_SBOM_PREFIX, suffix=".json", delete=False) as tmp_file:
            json.dump(sbom, tmp_file)
            return tmp_file.name

    async def _preprocess_sbom(self, sbom_path: str, _sbom_format: SBOMFormat) -> tuple[str, list[str]]:
        """Preprocess SBOM before analysis; returns (target_path, extra_temp_files_to_cleanup)."""
        return sbom_path, []

    @abstractmethod
    def _build_command_args(self, sbom_path: str) -> list[str]:
        """Build command line arguments. Must be implemented by subclasses."""
        raise NotImplementedError

    cli_timeout: int = 300

    max_retries: int = 0
    retry_delay: float = 2.0  # base delay in seconds, doubles each retry

    async def _execute_command(self, args: list[str]) -> tuple[bytes, bytes, int]:
        """Execute the CLI command and return stdout, stderr, returncode."""
        result = await run_process(args, self.cli_timeout)
        if result is None:
            logger.error("%s timed out after %ss", self.name, self.cli_timeout)
            return b"", f"{self.name} timed out after {self.cli_timeout} seconds".encode(), 1
        return result

    def _handle_error(self, stderr: bytes) -> dict[str, Any]:
        """Handle CLI error output."""
        error_msg = stderr.decode()
        logger.error(f"{self.name} failed: {error_msg}")
        return {"error": f"{self.name} analysis failed", "details": error_msg}

    def _parse_output(self, stdout: bytes) -> dict[str, Any]:
        """Parse CLI JSON output."""
        try:
            output_str = stdout.decode()
            if not output_str.strip():
                return {self.empty_result_key: []}

            result: dict[str, Any] = json.loads(output_str)
            return result
        except json.JSONDecodeError:
            output_str = stdout.decode()
            return {
                "error": f"Invalid JSON output from {self.name}",
                "output": output_str,
            }

    def _cleanup_files(self, paths: list[str]) -> None:
        """Remove temporary files."""
        for path in paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError as e:
                    logger.warning(f"Failed to cleanup temp file {path}: {e}")
