"""Tests for MR comment building.

Tests the pure _build_mr_comment function that generates GitLab MR comments
with scan results, severity tables, and status labels.
"""

from app.models.stats import Stats
from app.services.analysis.integrations import _build_mr_comment


class TestBuildMrCommentStatus:
    def test_ok_when_no_findings(self):
        stats = Stats()
        comment = _build_mr_comment("scan-1", stats, None)
        assert "[OK]" in comment

    def test_warning_when_risk_score_positive(self):
        stats = Stats(risk_score=25.0)
        comment = _build_mr_comment("scan-1", stats, None)
        assert "[WARNING]" in comment

    def test_alert_when_critical_findings(self):
        stats = Stats(critical=1, risk_score=80.0)
        comment = _build_mr_comment("scan-1", stats, None)
        assert "[ALERT]" in comment

    def test_alert_when_high_findings(self):
        stats = Stats(high=3, risk_score=50.0)
        comment = _build_mr_comment("scan-1", stats, None)
        assert "[ALERT]" in comment

    def test_alert_overrides_warning(self):
        """Critical/high should produce ALERT, not WARNING, even with risk_score > 0."""
        stats = Stats(critical=1, risk_score=80.0)
        comment = _build_mr_comment("scan-1", stats, None)
        assert "[ALERT]" in comment
        assert "[WARNING]" not in comment


class TestBuildMrCommentContent:
    def test_contains_scan_comment_marker(self):
        comment = _build_mr_comment("s1", Stats(), None)
        assert "<!-- dependency-control:scan-comment -->" in comment

    def test_contains_scan_id_marker(self):
        comment = _build_mr_comment("scan-xyz-123", Stats(), None)
        assert "<!-- dependency-control:scan-id:scan-xyz-123 -->" in comment

    def test_severity_counts_in_table(self):
        stats = Stats(critical=1, high=2, medium=3, low=4)
        comment = _build_mr_comment("s1", stats, None)
        assert "| Critical | 1 |" in comment
        assert "| High | 2 |" in comment
        assert "| Medium | 3 |" in comment
        assert "| Low | 4 |" in comment

    def test_risk_score_displayed(self):
        stats = Stats(risk_score=42.5)
        comment = _build_mr_comment("s1", stats, None)
        assert "42.5" in comment

    def test_includes_report_link_when_url_provided(self):
        comment = _build_mr_comment("s1", Stats(), "https://app.example.com/report")
        assert "[View Full Report](https://app.example.com/report)" in comment

    def test_no_report_link_when_url_none(self):
        comment = _build_mr_comment("s1", Stats(), None)
        assert "View Full Report" not in comment
