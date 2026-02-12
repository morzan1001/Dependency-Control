"""Tests for app.services.recommendation.insights."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.insights import (
    correlate_scorecard_with_vulnerabilities,
    analyze_cross_project_patterns,
)


def _vuln_finding(
    component="pkg",
    severity="CRITICAL",
    version="1.0.0",
    finding_id="vuln1",
):
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "id": finding_id,
        "details": {"cve_id": finding_id, "vulnerabilities": [{"id": finding_id}]},
    }


def _quality_finding(
    component="pkg",
    overall_score=3.0,
    critical_issues=None,
    project_url=None,
):
    return {
        "type": "quality",
        "severity": "HIGH",
        "component": component,
        "details": {
            "overall_score": overall_score,
            "critical_issues": critical_issues or [],
            "project_url": project_url,
            "failed_checks": [],
        },
    }


def _cross_project_data(projects, total_projects=None):
    return {
        "projects": projects,
        "total_projects": total_projects or len(projects),
    }


def _project(
    project_id="p1",
    project_name="App1",
    cves=None,
    packages=None,
    total_critical=0,
    total_high=0,
):
    return {
        "project_id": project_id,
        "project_name": project_name,
        "cves": cves or [],
        "packages": packages or [],
        "total_critical": total_critical,
        "total_high": total_high,
    }


class TestCorrelateScorceardEmpty:
    """Empty or missing findings."""

    def test_empty_vuln_returns_empty(self):
        result = correlate_scorecard_with_vulnerabilities([], [_quality_finding()])
        assert result == []

    def test_empty_quality_returns_empty(self):
        result = correlate_scorecard_with_vulnerabilities([_vuln_finding()], [])
        assert result == []

    def test_both_empty_returns_empty(self):
        result = correlate_scorecard_with_vulnerabilities([], [])
        assert result == []


class TestCorrelateScorceardCriticalUnmaintained:
    """Critical vuln in unmaintained package."""

    def test_critical_vuln_unmaintained_produces_recommendation(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg", overall_score=3.0,
                                    critical_issues=["Maintained"])]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 1

    def test_critical_vuln_unmaintained_type(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg", overall_score=3.0,
                                    critical_issues=["Maintained"])]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert rec.type == RecommendationType.CRITICAL_RISK

    def test_critical_vuln_unmaintained_priority_critical(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg", overall_score=3.0,
                                    critical_issues=["Maintained"])]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert rec.priority == Priority.CRITICAL


class TestCorrelateScorceardHighVulnLowScore:
    """High vuln in package with score below SCORECARD_UNMAINTAINED_THRESHOLD (5.0)."""

    def test_high_vuln_low_score_produces_recommendation(self):
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [_quality_finding(component="pkg", overall_score=3.5)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 1

    def test_high_vuln_low_score_type(self):
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [_quality_finding(component="pkg", overall_score=3.5)]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert rec.type == RecommendationType.CRITICAL_RISK

    def test_high_vuln_score_exactly_at_threshold_not_flagged(self):
        # SCORECARD_UNMAINTAINED_THRESHOLD is 5.0, condition is < 5.0
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [_quality_finding(component="pkg", overall_score=5.0)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0


class TestCorrelateScorceardNotFlagged:
    """Cases that should NOT produce recommendations."""

    def test_low_vuln_low_score_not_flagged(self):
        vulns = [_vuln_finding(component="pkg", severity="LOW")]
        quality = [_quality_finding(component="pkg", overall_score=2.0)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0

    def test_medium_vuln_low_score_not_flagged(self):
        vulns = [_vuln_finding(component="pkg", severity="MEDIUM")]
        quality = [_quality_finding(component="pkg", overall_score=2.0)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0

    def test_critical_vuln_well_maintained_not_flagged(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg", overall_score=8.0)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0

    def test_high_vuln_well_maintained_not_flagged(self):
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [_quality_finding(component="pkg", overall_score=7.5)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0

    def test_no_matching_component_not_flagged(self):
        vulns = [_vuln_finding(component="pkg-a", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg-b", overall_score=2.0)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0


class TestCorrelateScorceardAffectedComponents:
    """Affected components formatting."""

    def test_unmaintained_label_in_components(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL", version="1.0.0")]
        quality = [_quality_finding(component="pkg", overall_score=2.0,
                                    critical_issues=["Maintained"])]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert any("UNMAINTAINED" in c for c in rec.affected_components)

    def test_score_in_components(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL", version="1.0.0")]
        quality = [_quality_finding(component="pkg", overall_score=2.0)]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert any("2.0/10" in c for c in rec.affected_components)


class TestAnalyzeCrossProjectPatternsEmpty:
    """Empty or missing cross_project_data."""

    def test_empty_cross_project_data_returns_empty(self):
        result = analyze_cross_project_patterns([], [], {})
        assert result == []

    def test_none_cross_project_data_returns_empty(self):
        result = analyze_cross_project_patterns([], [], None)
        assert result == []

    def test_no_projects_key_returns_empty(self):
        result = analyze_cross_project_patterns([], [], {"other": "data"})
        assert result == []

    def test_empty_projects_list_returns_empty(self):
        data = _cross_project_data([])
        result = analyze_cross_project_patterns([], [], data)
        assert result == []


class TestAnalyzeCrossProjectPatternsSharedVuln:
    """CVE in 2+ projects (CROSS_PROJECT_MIN_OCCURRENCES = 2)."""

    def test_cve_in_two_projects_produces_recommendation(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
            _project(project_id="p2", project_name="App2", cves=["CVE-2024-001"]),
        ])
        result = analyze_cross_project_patterns([], [], data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert len(shared_recs) == 1

    def test_cve_in_two_projects_type(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
            _project(project_id="p2", project_name="App2", cves=["CVE-2024-001"]),
        ])
        result = analyze_cross_project_patterns([], [], data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert shared_recs[0].type == RecommendationType.SHARED_VULNERABILITY

    def test_cve_in_two_projects_affected_components(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
            _project(project_id="p2", project_name="App2", cves=["CVE-2024-001"]),
        ], total_projects=3)
        result = analyze_cross_project_patterns([], [], data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert any("CVE-2024-001" in c and "2/3" in c for c in shared_recs[0].affected_components)

    def test_cve_in_only_one_project_not_flagged(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
            _project(project_id="p2", project_name="App2", cves=["CVE-2024-002"]),
        ])
        result = analyze_cross_project_patterns([], [], data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert len(shared_recs) == 0


class TestAnalyzeCrossProjectPatternsInconsistentVersions:
    """Inconsistent package versions across projects."""

    def test_inconsistent_versions_produces_recommendation(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1",
                     packages=[{"name": "requests", "version": "2.28.0"}]),
            _project(project_id="p2", project_name="App2",
                     packages=[{"name": "requests", "version": "2.31.0"}]),
        ])
        result = analyze_cross_project_patterns([], [], data)
        pattern_recs = [r for r in result if r.type == RecommendationType.CROSS_PROJECT_PATTERN]
        assert len(pattern_recs) == 1

    def test_inconsistent_versions_type(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1",
                     packages=[{"name": "requests", "version": "2.28.0"}]),
            _project(project_id="p2", project_name="App2",
                     packages=[{"name": "requests", "version": "2.31.0"}]),
        ])
        result = analyze_cross_project_patterns([], [], data)
        pattern_recs = [r for r in result if r.type == RecommendationType.CROSS_PROJECT_PATTERN
                        and "inconsistency" in r.title.lower()]
        assert len(pattern_recs) == 1

    def test_same_versions_no_inconsistency(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1",
                     packages=[{"name": "requests", "version": "2.31.0"}]),
            _project(project_id="p2", project_name="App2",
                     packages=[{"name": "requests", "version": "2.31.0"}]),
        ])
        result = analyze_cross_project_patterns([], [], data)
        pattern_recs = [r for r in result if r.type == RecommendationType.CROSS_PROJECT_PATTERN
                        and "inconsistency" in r.title.lower()]
        assert len(pattern_recs) == 0


class TestAnalyzeCrossProjectPatternsPrioritizeProjects:
    """Projects with > 5 critical findings trigger prioritization recommendation."""

    def test_high_critical_projects_produces_recommendation(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", total_critical=10, total_high=5),
            _project(project_id="p2", project_name="App2", total_critical=2, total_high=1),
            _project(project_id="p3", project_name="App3", total_critical=1, total_high=0),
        ])
        result = analyze_cross_project_patterns([], [], data)
        priority_recs = [r for r in result if "Prioritize" in r.title or "prioritize" in r.title.lower()]
        assert len(priority_recs) == 1

    def test_high_critical_projects_priority_medium(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", total_critical=10, total_high=5),
            _project(project_id="p2", project_name="App2", total_critical=2, total_high=1),
            _project(project_id="p3", project_name="App3", total_critical=1, total_high=0),
        ])
        result = analyze_cross_project_patterns([], [], data)
        priority_recs = [r for r in result if "Prioritize" in r.title or "prioritize" in r.title.lower()]
        assert priority_recs[0].priority == Priority.MEDIUM

    def test_no_high_critical_no_prioritize_recommendation(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", total_critical=3, total_high=2),
            _project(project_id="p2", project_name="App2", total_critical=2, total_high=1),
            _project(project_id="p3", project_name="App3", total_critical=1, total_high=0),
        ])
        result = analyze_cross_project_patterns([], [], data)
        priority_recs = [r for r in result if "Prioritize" in r.title or "prioritize" in r.title.lower()]
        assert len(priority_recs) == 0

    def test_fewer_than_three_projects_no_prioritize(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1", total_critical=10, total_high=5),
            _project(project_id="p2", project_name="App2", total_critical=8, total_high=3),
        ])
        result = analyze_cross_project_patterns([], [], data)
        priority_recs = [r for r in result if "Prioritize" in r.title or "prioritize" in r.title.lower()]
        assert len(priority_recs) == 0


class TestAnalyzeCrossProjectPatternsMultipleRecommendations:
    """Can produce multiple recommendation types at once."""

    def test_shared_vuln_and_inconsistent_versions(self):
        data = _cross_project_data([
            _project(project_id="p1", project_name="App1",
                     cves=["CVE-2024-001"],
                     packages=[{"name": "requests", "version": "2.28.0"}]),
            _project(project_id="p2", project_name="App2",
                     cves=["CVE-2024-001"],
                     packages=[{"name": "requests", "version": "2.31.0"}]),
        ])
        result = analyze_cross_project_patterns([], [], data)
        types = {r.type for r in result}
        assert RecommendationType.SHARED_VULNERABILITY in types
        assert RecommendationType.CROSS_PROJECT_PATTERN in types
