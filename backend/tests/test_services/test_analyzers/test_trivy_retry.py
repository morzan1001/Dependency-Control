"""Tests for the TrivyAnalyzer retry policy: transient stderr patterns (including EOF) trigger retries."""

import pytest

from app.services.analyzers.trivy import TrivyAnalyzer


class TestTrivyRetryablePatternMatching:
    @pytest.mark.parametrize(
        "stderr_text",
        [
            "unexpected EOF",
            "unexpected eof",
            "layer cache missing",
            "failed to apply layers",
            "connection refused",
            "connection reset",
            "context deadline exceeded",
            "server unavailable",
            "i/o timeout",
        ],
    )
    def test_recognises_transient_error(self, stderr_text):
        analyzer = TrivyAnalyzer()
        assert analyzer._is_retryable_error(stderr_text.encode()) is True

    @pytest.mark.parametrize(
        "stderr_text",
        [
            "invalid argument: --foo",
            "unknown subcommand: scan-everything",
            "permission denied: /etc/trivy.yaml",
        ],
    )
    def test_non_transient_error_not_retried(self, stderr_text):
        analyzer = TrivyAnalyzer()
        assert analyzer._is_retryable_error(stderr_text.encode()) is False

    @pytest.mark.parametrize("stderr_text", ["", "  \n", "trivy timed out after 300 seconds"])
    def test_a_silent_or_timed_out_run_is_not_retried(self, stderr_text):
        assert TrivyAnalyzer()._is_retryable_error(stderr_text.encode()) is False

    def test_all_patterns_are_lowercase(self):
        # Guard against reintroducing an uppercase pattern that can never match
        # the lowercased stderr.
        for pattern in TrivyAnalyzer.retryable_patterns:
            assert pattern == pattern.lower(), pattern


def test_trivy_own_deadline_outlasts_cli_timeout():
    analyzer = TrivyAnalyzer()
    args = analyzer._build_command_args("sbom.json")
    assert int(args[args.index("--timeout") + 1].removesuffix("s")) > analyzer.cli_timeout
