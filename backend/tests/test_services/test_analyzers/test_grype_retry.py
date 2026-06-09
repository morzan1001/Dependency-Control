"""Tests for the GrypeAnalyzer retry policy.

Regression test for the silent-grype-fail issue: a single large Java project
was producing SCAN-ERROR-grype findings on intermittent grype failures
because the analyzer inherited ``max_retries = 0`` from CLIAnalyzer while
the sister trivy analyzer retries up to 3 times. The fix mirrors trivy's
policy. These tests pin that the policy survives future refactors.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.analyzers.grype import GrypeAnalyzer


SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
RETRYABLE_STDERR = b"context deadline exceeded while loading vuln DB"
NON_RETRYABLE_STDERR = b"invalid command line argument: --bogus"


def _exec_results(*results):
    """Build an AsyncMock that returns each tuple in sequence."""
    return AsyncMock(side_effect=list(results))


@pytest.fixture(autouse=True)
def _no_sleep():
    """Skip the exponential backoff sleep so tests run fast."""
    with patch("app.services.analyzers.cli_base.asyncio.sleep", new=AsyncMock()):
        yield


@pytest.fixture(autouse=True)
def _stub_temp_io():
    """Avoid hitting the filesystem during tests."""
    with (
        patch.object(GrypeAnalyzer, "_create_temp_sbom", return_value="/tmp/sbom.json"),
        patch.object(GrypeAnalyzer, "_cleanup_files"),
        patch.object(GrypeAnalyzer, "is_tool_available", return_value=True),
    ):
        yield


class TestGrypeRetryablePatternMatching:
    """The retry decision is driven entirely by _is_retryable_error matches."""

    @pytest.mark.parametrize(
        "stderr_text",
        [
            "context deadline exceeded",
            "Failed to update vulnerability database",
            "database integrity check failed",
            "i/o timeout",
            "EOF while parsing",
            "connection refused",
            "no such file or directory: /grype-db/vulnerability.db",
            "grype timed out after 600 seconds",
        ],
    )
    def test_recognises_transient_error(self, stderr_text):
        analyzer = GrypeAnalyzer()
        assert analyzer._is_retryable_error(stderr_text.encode()) is True

    @pytest.mark.parametrize(
        "stderr_text",
        [
            "invalid argument: --foo",
            "unknown subcommand: scan-everything",
            "permission denied: /etc/grype.yaml",
            "unsupported SBOM schema version 9.0",
        ],
    )
    def test_non_transient_error_not_retried(self, stderr_text):
        analyzer = GrypeAnalyzer()
        assert analyzer._is_retryable_error(stderr_text.encode()) is False

    @pytest.mark.parametrize("stderr_bytes", [b"", b"   ", b"\n\t "])
    def test_empty_stderr_is_retryable(self, stderr_bytes):
        # A non-zero exit with no stderr means grype was killed (signal/OOM) or
        # had its error swallowed (e.g. by --quiet). Retry rather than surface
        # an empty SCAN-ERROR-grype finding.
        analyzer = GrypeAnalyzer()
        assert analyzer._is_retryable_error(stderr_bytes) is True


class TestGrypeRetryLoop:
    """Verify the full analyze() flow retries / gives up correctly."""

    @pytest.mark.asyncio
    async def test_succeeds_on_first_attempt(self):
        analyzer = GrypeAnalyzer()
        mock_exec = _exec_results((b'{"matches": []}', b"", 0))

        with patch.object(analyzer, "_execute_command", mock_exec):
            result = await analyzer.analyze(SBOM)

        assert "error" not in result
        assert mock_exec.await_count == 1

    @pytest.mark.asyncio
    async def test_retries_until_success(self):
        analyzer = GrypeAnalyzer()
        mock_exec = _exec_results(
            (b"", RETRYABLE_STDERR, 1),
            (b"", RETRYABLE_STDERR, 1),
            (b'{"matches": []}', b"", 0),
        )

        with patch.object(analyzer, "_execute_command", mock_exec):
            result = await analyzer.analyze(SBOM)

        assert "error" not in result
        assert mock_exec.await_count == 3

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries(self):
        analyzer = GrypeAnalyzer()
        # 1 initial attempt + 3 retries = 4 total invocations
        mock_exec = _exec_results(
            *([(b"", RETRYABLE_STDERR, 1)] * 4),
        )

        with patch.object(analyzer, "_execute_command", mock_exec):
            result = await analyzer.analyze(SBOM)

        assert result.get("error") == "grype analysis failed"
        assert mock_exec.await_count == 4  # 1 + max_retries(3)

    @pytest.mark.asyncio
    async def test_non_retryable_error_fails_immediately(self):
        analyzer = GrypeAnalyzer()
        mock_exec = _exec_results((b"", NON_RETRYABLE_STDERR, 1))

        with patch.object(analyzer, "_execute_command", mock_exec):
            result = await analyzer.analyze(SBOM)

        assert result.get("error") == "grype analysis failed"
        assert mock_exec.await_count == 1  # no retries on non-transient errors

    @pytest.mark.asyncio
    async def test_retries_on_empty_stderr(self):
        # Regression: grype killed/quiet -> empty stderr on a non-zero exit.
        # This is the exact failure mode that previously slipped past the retry
        # because the patterns were matched against an empty string.
        analyzer = GrypeAnalyzer()
        mock_exec = _exec_results(
            (b"", b"", 1),
            (b'{"matches": []}', b"", 0),
        )

        with patch.object(analyzer, "_execute_command", mock_exec):
            result = await analyzer.analyze(SBOM)

        assert "error" not in result
        assert mock_exec.await_count == 2


class TestGrypeRetryPolicyConfig:
    """Lock the policy values so a future refactor can't silently remove them."""

    def test_max_retries_matches_trivy(self):
        assert GrypeAnalyzer.max_retries == 3

    def test_retry_delay_is_three_seconds(self):
        assert GrypeAnalyzer.retry_delay == 3.0

    def test_cli_timeout_extended_beyond_default(self):
        # The CLIAnalyzer default is 300; grype needs more for large Java SBOMs.
        assert GrypeAnalyzer.cli_timeout >= 600

    def test_quiet_flag_not_passed(self):
        # Regression: --quiet suppresses grype's stderr, which the retry logic
        # inspects. It must never be re-added or transient failures go silent.
        analyzer = GrypeAnalyzer()
        args = analyzer._build_command_args("sbom.json", None)
        assert "--quiet" not in args
        assert "-q" not in args
