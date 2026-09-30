"""Tests for the MR/PR scan comment body."""

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS
from app.models.stats import Stats
from app.services.analysis.integrations import _build_scan_comment

_URL = "https://app.example.com/projects/p1/scans/s1"


def _comment(stats: Stats, status=SCAN_STATUS_COMPLETED, error=None) -> str:
    return _build_scan_comment(stats, _URL, status, error)


class TestBuildScanCommentStatus:
    def test_ok_when_no_findings(self):
        assert "[OK]" in _comment(Stats())

    def test_warning_when_risk_score_positive(self):
        assert "[WARNING]" in _comment(Stats(risk_score=25.0))

    def test_alert_when_high_findings(self):
        assert "[ALERT]" in _comment(Stats(high=3, risk_score=50.0))

    def test_alert_overrides_warning(self):
        """Critical/high should produce ALERT, not WARNING, even with risk_score > 0."""
        comment = _comment(Stats(critical=1, risk_score=80.0))
        assert "[ALERT]" in comment
        assert "[WARNING]" not in comment

    def test_a_completed_scan_says_completed(self):
        assert "**Status:** Completed\n" in _comment(Stats())

    def test_a_scan_with_a_failed_analyzer_says_so_and_is_not_ok(self):
        error = "analyzers failed or returned partial results: grype"
        comment = _comment(Stats(), SCAN_STATUS_COMPLETED_WITH_ERRORS, error)

        assert f"**Status:** Completed with errors: {error}" in comment
        assert "[WARNING]" in comment
        assert "[OK]" not in comment


class TestBuildScanCommentContent:
    def test_contains_scan_comment_marker(self):
        assert "<!-- dependency-control:scan-comment -->" in _comment(Stats())

    def test_severity_counts_in_table(self):
        comment = _comment(Stats(critical=1, high=2, medium=3, low=4))
        assert "| Critical | 1 |" in comment
        assert "| High | 2 |" in comment
        assert "| Medium | 3 |" in comment
        assert "| Low | 4 |" in comment

    def test_risk_score_displayed(self):
        assert "42.5" in _comment(Stats(risk_score=42.5))

    def test_links_the_report(self):
        assert f"[View Full Report]({_URL})" in _comment(Stats())
