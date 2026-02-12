"""Tests for app.services.recommendation.trends."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.trends import (
    analyze_regressions,
    analyze_recurring_issues,
)


def _vuln(severity="CRITICAL", component="pkg", cve_id="CVE-2024-001"):
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "id": cve_id,
        "details": {"cve_id": cve_id},
    }


def _non_vuln(component="pkg", finding_id="finding-1"):
    return {
        "type": "license",
        "severity": "MEDIUM",
        "component": component,
        "id": finding_id,
        "details": {},
    }


def _scan(scan_id, findings):
    return {
        "_id": scan_id,
        "findings_summary": findings,
    }


def _scan_finding(cve_id="CVE-2024-001", severity="CRITICAL", component="pkg"):
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "id": cve_id,
        "details": {"cve_id": cve_id},
        "description": f"Description for {cve_id}",
    }


class TestAnalyzeRegressionsEmpty:
    """No findings at all."""

    def test_empty_both_returns_empty(self):
        assert analyze_regressions([], []) == []

    def test_empty_current_returns_empty(self):
        assert analyze_regressions([], [_vuln()]) == []


class TestAnalyzeRegressionsNewCriticalVuln:
    """New critical vulnerability triggers HIGH priority regression."""

    def test_new_critical_vuln_produces_recommendation(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 1

    def test_new_critical_vuln_type(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.type == RecommendationType.REGRESSION_DETECTED

    def test_new_critical_vuln_priority_high(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.HIGH

    def test_new_critical_vuln_impact_critical_count(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.impact["critical"] == 1

    def test_new_critical_vuln_affected_components(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999", component="lodash")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert "lodash" in rec.affected_components

    def test_new_critical_vuln_action_cves(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert "CVE-2024-999" in rec.action["new_critical_cves"]


class TestAnalyzeRegressionsNewHighVuln:
    """New high vulnerability (no critical) triggers MEDIUM priority."""

    def test_new_high_vuln_produces_recommendation(self):
        current = [_vuln(severity="HIGH", cve_id="CVE-2024-100")]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 1

    def test_new_high_vuln_priority_medium(self):
        current = [_vuln(severity="HIGH", cve_id="CVE-2024-100")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.MEDIUM

    def test_new_high_vuln_impact_high_count(self):
        current = [_vuln(severity="HIGH", cve_id="CVE-2024-100")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.impact["high"] == 1
        assert rec.impact["critical"] == 0


class TestAnalyzeRegressionsDeltaThreshold:
    """Finding delta > FINDING_DELTA_THRESHOLD (10) but no critical/high."""

    def test_delta_above_threshold_produces_low_priority(self):
        # 12 new non-vuln findings, 0 previous => delta = 12 > 10
        current = [_non_vuln(finding_id=f"f-{i}") for i in range(12)]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 1

    def test_delta_above_threshold_priority_low(self):
        current = [_non_vuln(finding_id=f"f-{i}") for i in range(12)]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.LOW

    def test_delta_above_threshold_type(self):
        current = [_non_vuln(finding_id=f"f-{i}") for i in range(12)]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.type == RecommendationType.REGRESSION_DETECTED

    def test_delta_exactly_at_threshold_no_recommendation(self):
        # delta = 10, threshold is > 10, so no recommendation
        current = [_non_vuln(finding_id=f"f-{i}") for i in range(10)]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 0

    def test_delta_below_threshold_no_recommendation(self):
        current = [_non_vuln(finding_id=f"f-{i}") for i in range(5)]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 0


class TestAnalyzeRegressionsSameFindings:
    """Same findings in both scans produce no regression."""

    def test_same_findings_no_regression(self):
        finding = _vuln(severity="CRITICAL", cve_id="CVE-2024-001")
        result = analyze_regressions([finding], [finding])
        assert len(result) == 0

    def test_fewer_findings_no_regression(self):
        previous = [_vuln(cve_id="CVE-2024-001"), _vuln(cve_id="CVE-2024-002")]
        current = [_vuln(cve_id="CVE-2024-001")]
        result = analyze_regressions(current, previous)
        assert len(result) == 0


class TestAnalyzeRegressionsMixedNewFindings:
    """Mixed new critical and high together."""

    def test_both_critical_and_high_priority_is_high(self):
        current = [
            _vuln(severity="CRITICAL", cve_id="CVE-2024-100"),
            _vuln(severity="HIGH", cve_id="CVE-2024-200"),
        ]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.HIGH

    def test_title_includes_counts(self):
        current = [
            _vuln(severity="CRITICAL", cve_id="CVE-2024-100"),
            _vuln(severity="HIGH", cve_id="CVE-2024-200"),
            _vuln(severity="HIGH", cve_id="CVE-2024-201"),
        ]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert "1 critical" in rec.title
        assert "2 high" in rec.title


class TestAnalyzeRecurringIssuesEmpty:
    """Empty or insufficient history."""

    def test_empty_history_returns_empty(self):
        assert analyze_recurring_issues([]) == []

    def test_single_scan_returns_empty(self):
        history = [_scan("scan1", [_scan_finding()])]
        result = analyze_recurring_issues(history)
        assert len(result) == 0


class TestAnalyzeRecurringIssuesThreshold:
    """CVE must appear in 3+ scans to be recurring."""

    def test_cve_in_two_scans_no_recommendation(self):
        history = [
            _scan("scan1", [_scan_finding(cve_id="CVE-2024-001")]),
            _scan("scan2", [_scan_finding(cve_id="CVE-2024-001")]),
        ]
        result = analyze_recurring_issues(history)
        assert len(result) == 0

    def test_cve_in_three_scans_produces_recommendation(self):
        history = [
            _scan("scan1", [_scan_finding(cve_id="CVE-2024-001")]),
            _scan("scan2", [_scan_finding(cve_id="CVE-2024-001")]),
            _scan("scan3", [_scan_finding(cve_id="CVE-2024-001")]),
        ]
        result = analyze_recurring_issues(history)
        assert len(result) == 1

    def test_cve_in_three_scans_type(self):
        history = [
            _scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001")])
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert rec.type == RecommendationType.RECURRING_VULNERABILITY

    def test_cve_in_four_scans_still_one_recommendation(self):
        history = [
            _scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001")])
            for i in range(4)
        ]
        result = analyze_recurring_issues(history)
        assert len(result) == 1


class TestAnalyzeRecurringIssuesPriority:
    """Priority depends on whether any recurring CVE is CRITICAL."""

    def test_critical_recurring_gives_medium_priority(self):
        history = [
            _scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", severity="CRITICAL")])
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.MEDIUM

    def test_high_recurring_gives_low_priority(self):
        history = [
            _scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", severity="HIGH")])
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.LOW

    def test_medium_recurring_gives_low_priority(self):
        history = [
            _scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", severity="MEDIUM")])
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.LOW

    def test_mixed_critical_and_high_gives_medium_priority(self):
        history = [
            _scan(f"scan{i}", [
                _scan_finding(cve_id="CVE-2024-001", severity="CRITICAL"),
                _scan_finding(cve_id="CVE-2024-002", severity="HIGH"),
            ])
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.MEDIUM


class TestAnalyzeRecurringIssuesAffectedComponents:
    """Affected components list should contain CVE and component info."""

    def test_affected_components_format(self):
        history = [
            _scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", component="lodash")])
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert any("CVE-2024-001" in c and "lodash" in c for c in rec.affected_components)

    def test_affected_components_include_scan_count(self):
        history = [
            _scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001")])
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert any("3 scans" in c for c in rec.affected_components)


class TestAnalyzeRecurringIssuesNonVulnSkipped:
    """Non-vulnerability findings are not tracked for recurrence."""

    def test_non_vuln_not_counted(self):
        non_vuln_finding = {
            "type": "license",
            "severity": "MEDIUM",
            "component": "pkg",
            "id": "lic-1",
            "details": {},
            "description": "License issue",
        }
        history = [
            _scan(f"scan{i}", [non_vuln_finding])
            for i in range(5)
        ]
        result = analyze_recurring_issues(history)
        assert len(result) == 0
