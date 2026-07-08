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

    def test_all_patterns_are_lowercase(self):
        # Guard against reintroducing an uppercase pattern that can never match
        # the lowercased stderr.
        for pattern in TrivyAnalyzer._RETRYABLE_PATTERNS:
            assert pattern == pattern.lower(), pattern
