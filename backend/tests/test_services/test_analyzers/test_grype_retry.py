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


class TestGrypeRetryPolicyConfig:
    """Lock the policy values so a future refactor can't silently remove them."""

    def test_max_retries_matches_trivy(self):
        assert GrypeAnalyzer.max_retries == 3

    def test_retry_delay_is_three_seconds(self):
        assert GrypeAnalyzer.retry_delay == 3.0

    def test_cli_timeout_extended_beyond_default(self):
        # The CLIAnalyzer default is 300; grype needs more for large Java SBOMs.
        assert GrypeAnalyzer.cli_timeout >= 600
