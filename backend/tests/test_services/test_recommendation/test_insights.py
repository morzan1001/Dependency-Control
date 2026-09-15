"""Tests for app.services.recommendation.insights."""

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.insights import (
    analyze_cross_project_patterns,
    correlate_scorecard_with_vulnerabilities,
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
        "details": {"vulnerabilities": [{"id": finding_id}], "fixed_version": None},
    }


def _quality_finding(
    component="pkg",
    overall_score=3.0,
    critical_issues=None,
    project_url=None,
):
    critical = critical_issues or []
    # Mirrors the stored aggregated shape: per-issue scorecard fields live one
    # level down in quality_issues[].details, only the roll-ups sit at the top.
    return {
        "type": "quality",
        "severity": "HIGH",
        "component": component,
        "details": {
            "overall_score": overall_score,
            "has_maintenance_issues": "Maintained" in critical,
            "issue_count": 1,
            "quality_issues": [
                {
                    "id": f"SCORECARD-{component}",
                    "type": "scorecard",
                    "severity": "HIGH",
                    "details": {
                        "overall_score": overall_score,
                        "critical_issues": critical,
                        "failed_checks": [],
                        "project_url": project_url,
                    },
                }
            ],
        },
    }


def _cross_project_data(projects, total_projects=None, shared_packages=None, projects_compared=None):
    return {
        "projects": projects,
        "shared_packages": shared_packages or [],
        "total_projects": total_projects or len(projects),
        "projects_compared": projects_compared if projects_compared is not None else len(projects),
    }


def _shared_package(name="requests", versions=("2.28.0", "2.31.0"), project_count=2):
    """One row of the cross-project package aggregation, which counts in Mongo over every
    dependency row rather than sampling each scan."""
    return {
        "name": name,
        "versions": list(versions),
        "version_count": len(versions),
        "project_count": project_count,
    }


def _project(
    project_id="p1",
    project_name="App1",
    cves=None,
    total_critical=0,
    total_high=0,
):
    return {
        "project_id": project_id,
        "project_name": project_name,
        "cves": cves or [],
        "total_critical": total_critical,
        "total_high": total_high,
    }


class TestCorrelateScorceardEmpty:
    @pytest.mark.parametrize(
        ("vulns", "quality"),
        [
            pytest.param([], [_quality_finding()], id="no-vulns"),
            pytest.param([_vuln_finding()], [], id="no-quality"),
            pytest.param([], [], id="neither"),
        ],
    )
    def test_missing_side_returns_empty(self, vulns, quality):
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert result == []


class TestCorrelateScorceardCriticalUnmaintained:
    def test_critical_vuln_unmaintained_produces_recommendation(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg", overall_score=3.0, critical_issues=["Maintained"])]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 1

    def test_critical_vuln_unmaintained_type(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg", overall_score=3.0, critical_issues=["Maintained"])]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert rec.type == RecommendationType.CRITICAL_RISK

    def test_critical_vuln_unmaintained_priority_critical(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
        quality = [_quality_finding(component="pkg", overall_score=3.0, critical_issues=["Maintained"])]
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
        # SCORECARD_UNMAINTAINED_THRESHOLD is 5.0; condition is score < 5.0.
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [_quality_finding(component="pkg", overall_score=5.0)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0


class TestCorrelateScorceardNotFlagged:
    @pytest.mark.parametrize(
        ("vuln_component", "severity", "quality_component", "overall_score"),
        [
            pytest.param("pkg", "LOW", "pkg", 2.0, id="low-vuln-low-score"),
            pytest.param("pkg", "MEDIUM", "pkg", 2.0, id="medium-vuln-low-score"),
            pytest.param("pkg", "CRITICAL", "pkg", 8.0, id="critical-vuln-well-maintained"),
            pytest.param("pkg", "HIGH", "pkg", 7.5, id="high-vuln-well-maintained"),
            pytest.param("pkg-a", "CRITICAL", "pkg-b", 2.0, id="no-matching-component"),
        ],
    )
    def test_not_flagged(self, vuln_component, severity, quality_component, overall_score):
        vulns = [_vuln_finding(component=vuln_component, severity=severity)]
        quality = [_quality_finding(component=quality_component, overall_score=overall_score)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 0


class TestCorrelateScorceardAffectedComponents:
    @pytest.mark.parametrize(
        ("critical_issues", "expected_fragment"),
        [
            pytest.param(["Maintained"], "UNMAINTAINED", id="unmaintained-label"),
            pytest.param(None, "2.0/10", id="score"),
        ],
    )
    def test_component_label(self, critical_issues, expected_fragment):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL", version="1.0.0")]
        quality = [_quality_finding(component="pkg", overall_score=2.0, critical_issues=critical_issues)]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert any(expected_fragment in c for c in rec.affected_components)


class TestAnalyzeCrossProjectPatternsEmpty:
    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="empty-dict"),
            pytest.param(None, id="none"),
            pytest.param({"other": "data"}, id="no-projects-key"),
            pytest.param(_cross_project_data([]), id="empty-projects-list"),
        ],
    )
    def test_returns_empty(self, data):
        result = analyze_cross_project_patterns([], [], data)
        assert result == []


class TestAnalyzeCrossProjectPatternsSharedVuln:
    """CVE in 2+ projects (CROSS_PROJECT_MIN_OCCURRENCES = 2)."""

    @pytest.mark.parametrize(
        ("p1_cves", "p2_cves", "expected"),
        [
            pytest.param(["CVE-2024-001"], ["CVE-2024-001"], 1, id="same-cve-in-both"),
            pytest.param(["CVE-2024-001"], ["CVE-2024-002"], 0, id="cve-in-one-project-only"),
        ],
    )
    def test_shared_recommendation_needs_a_repeated_cve(self, p1_cves, p2_cves, expected):
        data = _cross_project_data(
            [
                _project(project_id="p1", project_name="App1", cves=p1_cves),
                _project(project_id="p2", project_name="App2", cves=p2_cves),
            ]
        )
        result = analyze_cross_project_patterns([], [], data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert len(shared_recs) == expected

    def test_cve_in_two_projects_affected_components(self):
        data = _cross_project_data(
            [
                _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
                _project(project_id="p2", project_name="App2", cves=["CVE-2024-001"]),
            ],
            total_projects=3,
            projects_compared=2,
        )
        result = analyze_cross_project_patterns([], [], data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert any("CVE-2024-001" in c and "2/2 projects compared" in c for c in shared_recs[0].affected_components)
        assert "compared across 2 of your 3 projects" in shared_recs[0].description


class TestAnalyzeCrossProjectPatternsInconsistentVersions:
    def test_inconsistent_versions_produces_recommendation(self):
        data = _cross_project_data(
            [_project(project_id="p1"), _project(project_id="p2")],
            shared_packages=[_shared_package()],
        )
        result = analyze_cross_project_patterns([], [], data)
        pattern_recs = [r for r in result if r.type == RecommendationType.CROSS_PROJECT_PATTERN]
        assert len(pattern_recs) == 1

    @pytest.mark.parametrize(
        ("shared_packages", "expected"),
        [
            pytest.param([_shared_package()], 1, id="multi-version-package"),
            # The aggregation only emits a package whose version_count exceeds one.
            pytest.param([], 0, id="no-multi-version-package"),
        ],
    )
    def test_inconsistency_recommendation(self, shared_packages, expected):
        data = _cross_project_data(
            [_project(project_id="p1"), _project(project_id="p2")],
            shared_packages=shared_packages,
        )
        result = analyze_cross_project_patterns([], [], data)
        pattern_recs = [
            r
            for r in result
            if r.type == RecommendationType.CROSS_PROJECT_PATTERN and "inconsistency" in r.title.lower()
        ]
        assert len(pattern_recs) == expected


class TestAnalyzeCrossProjectPatternsPrioritizeProjects:
    """Projects with > 5 critical findings trigger prioritization recommendation."""

    @pytest.mark.parametrize(
        ("projects", "expected"),
        [
            pytest.param(
                [
                    _project(project_id="p1", project_name="App1", total_critical=10, total_high=5),
                    _project(project_id="p2", project_name="App2", total_critical=2, total_high=1),
                    _project(project_id="p3", project_name="App3", total_critical=1, total_high=0),
                ],
                1,
                id="one-project-above-critical-threshold",
            ),
            pytest.param(
                [
                    _project(project_id="p1", project_name="App1", total_critical=3, total_high=2),
                    _project(project_id="p2", project_name="App2", total_critical=2, total_high=1),
                    _project(project_id="p3", project_name="App3", total_critical=1, total_high=0),
                ],
                0,
                id="all-projects-below-critical-threshold",
            ),
            pytest.param(
                [
                    _project(project_id="p1", project_name="App1", total_critical=10, total_high=5),
                    _project(project_id="p2", project_name="App2", total_critical=8, total_high=3),
                ],
                0,
                id="fewer-than-three-projects",
            ),
        ],
    )
    def test_prioritize_recommendation(self, projects, expected):
        data = _cross_project_data(projects)
        result = analyze_cross_project_patterns([], [], data)
        priority_recs = [r for r in result if "Prioritize" in r.title or "prioritize" in r.title.lower()]
        assert len(priority_recs) == expected

    def test_high_critical_projects_priority_medium(self):
        data = _cross_project_data(
            [
                _project(project_id="p1", project_name="App1", total_critical=10, total_high=5),
                _project(project_id="p2", project_name="App2", total_critical=2, total_high=1),
                _project(project_id="p3", project_name="App3", total_critical=1, total_high=0),
            ]
        )
        result = analyze_cross_project_patterns([], [], data)
        priority_recs = [r for r in result if "Prioritize" in r.title or "prioritize" in r.title.lower()]
        assert priority_recs[0].priority == Priority.MEDIUM


class TestAnalyzeCrossProjectPatternsMultipleRecommendations:
    def test_shared_vuln_and_inconsistent_versions(self):
        data = _cross_project_data(
            [
                _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
                _project(project_id="p2", project_name="App2", cves=["CVE-2024-001"]),
            ],
            shared_packages=[_shared_package()],
        )
        result = analyze_cross_project_patterns([], [], data)
        types = {r.type for r in result}
        assert RecommendationType.SHARED_VULNERABILITY in types
        assert RecommendationType.CROSS_PROJECT_PATTERN in types


def test_scorecard_correlation_bridges_a_requalified_vulnerability_component():
    """Quality findings keep the inventory name; vulnerability components are group-qualified."""
    recs = correlate_scorecard_with_vulnerabilities(
        [_vuln_finding(component="com.fasterxml.jackson.core:jackson-databind")],
        [_quality_finding(component="jackson-databind", overall_score=2.0, critical_issues=["Maintained"])],
    )

    assert len(recs) == 1
    assert recs[0].affected_components[0].startswith("com.fasterxml.jackson.core:jackson-databind@")


def test_scorecard_correlation_does_not_guess_an_ambiguous_artifact_name():
    recs = correlate_scorecard_with_vulnerabilities(
        [_vuln_finding(component="@angular/core")],
        [
            _quality_finding(component="@angular-devkit/core", overall_score=2.0, critical_issues=["Maintained"]),
            _quality_finding(component="@messageformat/core", overall_score=2.0, critical_issues=["Maintained"]),
        ],
    )

    assert recs == []
