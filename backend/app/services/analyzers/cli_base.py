"""
CLI Analyzer Base Class

Provides shared functionality for analyzers that execute CLI tools (trivy, grype, etc.).
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from .base import Analyzer

logger = logging.getLogger(__name__)


class CLIAnalyzer(Analyzer):
    """
    Base class for analyzers that execute CLI tools.

    Provides common functionality:
    - Temporary file management for SBOM input
    - Subprocess execution
    - JSON output parsing
    - Cleanup handling
    """

    # Subclasses must override these
    cli_command: str = ""
    empty_result_key: str = "results"

    def is_tool_available(self) -> bool:
        """Check if the CLI tool is available in the system PATH."""
        if not self.cli_command:
            return False
        return shutil.which(self.cli_command) is not None

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run CLI analysis with automatic temp file management."""
        # Check tool availability first
        if not self.is_tool_available():
            logger.warning(f"{self.name}: CLI tool '{self.cli_command}' not found in PATH")
            return {
                "error": f"CLI tool '{self.cli_command}' not found",
                "details": f"Please install {self.cli_command} and ensure it's in your PATH",
                self.empty_result_key: [],
            }

        tmp_sbom_path: Optional[str] = None
        extra_paths: List[str] = []

        try:
            # Create temporary file for SBOM
            tmp_sbom_path = self._create_temp_sbom(sbom)

            # Allow subclasses to preprocess (e.g., convert SBOM format)
            target_path, extra_paths = await self._preprocess_sbom(sbom, tmp_sbom_path, settings)

            # Build and execute command
            args = self._build_command_args(target_path, settings)
            stdout, stderr, returncode = await self._execute_command(args)

            # Handle errors
            if returncode != 0:
                return self._handle_error(stderr)

            # Parse and return result
            return self._parse_output(stdout)

        except Exception as e:
            logger.exception(f"Exception during {self.name} analysis")
            return {"error": f"Exception during {self.name} analysis: {str(e)}"}

        finally:
            # Cleanup temp files
            self._cleanup_files([tmp_sbom_path] + extra_paths)

    def _create_temp_sbom(self, sbom: Dict[str, Any]) -> str:
        """Create a temporary file containing the SBOM JSON."""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp_file:
            json.dump(sbom, tmp_file)
            return tmp_file.name

    async def _preprocess_sbom(
        self,
        sbom: Dict[str, Any],
        tmp_sbom_path: str,
        settings: Optional[Dict[str, Any]],
    ) -> Tuple[str, List[str]]:
        """
        Preprocess SBOM before analysis.

        Override in subclasses for format conversion, etc.

        Returns:
            Tuple of (target_path, list_of_extra_temp_files_to_cleanup)
        """
        return tmp_sbom_path, []

    @abstractmethod
    def _build_command_args(self, sbom_path: str, settings: Optional[Dict[str, Any]]) -> List[str]:
        """Build command line arguments. Must be implemented by subclasses."""
        raise NotImplementedError

    async def _execute_command(self, args: List[str]) -> Tuple[bytes, bytes, int]:
        """Execute the CLI command and return stdout, stderr, returncode."""
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return stdout, stderr, process.returncode

    def _handle_error(self, stderr: bytes) -> Dict[str, Any]:
        """Handle CLI error output."""
        error_msg = stderr.decode()
        logger.error(f"{self.name} failed: {error_msg}")
        return {"error": f"{self.name} analysis failed", "details": error_msg}

    def _parse_output(self, stdout: bytes) -> Dict[str, Any]:
        """Parse CLI JSON output."""
        try:
            output_str = stdout.decode()
            if not output_str.strip():
                return {self.empty_result_key: []}

            return json.loads(output_str)
        except json.JSONDecodeError:
            output_str = stdout.decode()
            return {
                "error": f"Invalid JSON output from {self.name}",
                "output": output_str,
            }

    def _cleanup_files(self, paths: List[Optional[str]]) -> None:
        """Remove temporary files."""
        for path in paths:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError as e:
                    logger.warning(f"Failed to cleanup temp file {path}: {e}")
