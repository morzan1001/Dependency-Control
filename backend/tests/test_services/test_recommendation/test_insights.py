"""Tests for app.services.recommendation.insights."""

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.insights import (
    analyze_cross_project_patterns,
    correlate_scorecard_with_vulnerabilities,
)
from tests.helpers.findings import stored_vulnerability


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
        "details": {"vulnerabilities": [{"id": finding_id, "severity": severity}], "fixed_version": None},
    }


def _quality_finding(
    component="pkg",
    overall_score=3.0,
    critical_issues=None,
    project_url=None,
    has_maintenance_issues=None,
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
            "has_maintenance_issues": (
                "Maintained" in critical if has_maintenance_issues is None else has_maintenance_issues
            ),
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


def _cross_project_data(projects, total_projects=None, shared_packages=None):
    return {
        "projects": projects,
        "shared_packages": shared_packages or [],
        "total_projects": total_projects or len(projects),
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
    """High vuln in a package the scorecard analyzer flagged, whatever threshold the project set."""

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

    def test_a_score_flagged_under_a_raised_project_threshold_counts(self):
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [_quality_finding(component="pkg", overall_score=6.0)]
        result = correlate_scorecard_with_vulnerabilities(vulns, quality)
        assert len(result) == 1

    def test_the_description_names_the_flag_rather_than_a_cut(self):
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [_quality_finding(component="pkg", overall_score=3.5)]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert "1 are in packages flagged by OpenSSF Scorecard" in rec.description
        assert "below" not in rec.description

    def test_only_the_aggregated_maintenance_flag_marks_a_package_unmaintained(self):
        vulns = [_vuln_finding(component="pkg", severity="HIGH")]
        quality = [
            _quality_finding(
                component="pkg", overall_score=3.5, critical_issues=["Maintained"], has_maintenance_issues=False
            )
        ]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]
        assert rec.impact["unmaintained_count"] == 0


class TestCorrelateScorceardNotFlagged:
    @pytest.mark.parametrize(
        ("vuln_component", "severity", "quality_component", "overall_score"),
        [
            pytest.param("pkg", "LOW", "pkg", 2.0, id="low-vuln-low-score"),
            pytest.param("pkg", "MEDIUM", "pkg", 2.0, id="medium-vuln-low-score"),
            pytest.param("pkg", "CRITICAL", "pkg", None, id="critical-vuln-no-scorecard"),
            pytest.param("pkg", "HIGH", "pkg", None, id="high-vuln-no-scorecard"),
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
    def test_no_other_project_with_a_scan_returns_empty(self):
        assert analyze_cross_project_patterns(_cross_project_data([], total_projects=4)) == []


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
        result = analyze_cross_project_patterns(data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert len(shared_recs) == expected

    def test_cve_in_two_projects_affected_components(self):
        data = _cross_project_data(
            [
                _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
                _project(project_id="p2", project_name="App2", cves=["CVE-2024-001"]),
            ],
            total_projects=3,
        )
        result = analyze_cross_project_patterns(data)
        shared_recs = [r for r in result if r.type == RecommendationType.SHARED_VULNERABILITY]
        assert shared_recs[0].affected_components == []
        assert shared_recs[0].action["cves"] == [
            {"cve": "CVE-2024-001", "affected_projects": ["App1", "App2"], "total_affected": 2}
        ]
        assert "compared across 2 of your 3 projects" in shared_recs[0].description
        # The per-project CVE lists carry no severity to break the count down by.
        assert shared_recs[0].impact == {"total": 1}


class TestAnalyzeCrossProjectPatternsInconsistentVersions:
    def test_inconsistent_versions_produces_recommendation(self):
        data = _cross_project_data(
            [_project(project_id="p1"), _project(project_id="p2")],
            shared_packages=[_shared_package()],
        )
        result = analyze_cross_project_patterns(data)
        pattern_recs = [r for r in result if r.type == RecommendationType.CROSS_PROJECT_PATTERN]
        assert len(pattern_recs) == 1
        assert pattern_recs[0].impact == {"total": 0}
        assert pattern_recs[0].action["packages_total"] == 1

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
        result = analyze_cross_project_patterns(data)
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
        result = analyze_cross_project_patterns(data)
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
        result = analyze_cross_project_patterns(data)
        priority_recs = [r for r in result if "Prioritize" in r.title or "prioritize" in r.title.lower()]
        assert priority_recs[0].priority == Priority.MEDIUM
        assert priority_recs[0].affected_components == []
        assert [p["name"] for p in priority_recs[0].action["priority_projects"]] == ["App1", "App2", "App3"]


class TestCrossProjectCardsStateTheirOwnNumbers:
    def test_the_shared_cve_text_names_the_project_threshold_not_the_cve_count(self):
        cves = [f"CVE-2024-{n:04d}" for n in range(12)]
        data = _cross_project_data(
            [
                _project(project_id="p1", project_name="App1", cves=cves),
                _project(project_id="p2", project_name="App2", cves=cves),
            ]
        )

        [shared] = [
            r for r in analyze_cross_project_patterns(data) if r.type == RecommendationType.SHARED_VULNERABILITY
        ]

        assert shared.description.startswith(
            "These CVEs appear in 2 or more of your projects, compared across all 2 of your projects."
        )

    def test_the_most_affected_card_books_no_other_projects_findings_as_its_impact(self):
        counts = [(400, 900), (250, 700), (120, 300), (2, 10)]
        projects = [
            _project(project_id=f"p{n}", project_name=f"App{n}", total_critical=critical, total_high=high)
            for n, (critical, high) in enumerate(counts)
        ]

        [card] = [r for r in analyze_cross_project_patterns(_cross_project_data(projects)) if "Prioritize" in r.title]

        assert card.impact == {"total": 0}
        assert card.action["priority_projects"][0] == {"name": "App0", "id": "p0", "critical": 400, "high": 900}


class TestAnalyzeCrossProjectPatternsMultipleRecommendations:
    def test_shared_vuln_and_inconsistent_versions(self):
        data = _cross_project_data(
            [
                _project(project_id="p1", project_name="App1", cves=["CVE-2024-001"]),
                _project(project_id="p2", project_name="App2", cves=["CVE-2024-001"]),
            ],
            shared_packages=[_shared_package()],
        )
        result = analyze_cross_project_patterns(data)
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


def test_scorecard_correlation_names_an_advisory_by_its_cve():
    finding = _vuln_finding(component="log4j-core")
    finding["details"]["vulnerabilities"] = [
        {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "severity": "CRITICAL"},
        {"id": "CVE-2021-45046", "severity": "CRITICAL", "waived": True},
    ]

    [rec] = correlate_scorecard_with_vulnerabilities([finding], [_quality_finding(component="log4j-core")])

    assert rec.action["packages"][0]["cves"] == ["CVE-2021-44228"]


class TestCorrelateScorecardUnmaintainedWithoutScorecard:
    def _maintainer_only_finding(self, component="pkg"):
        return {
            "type": "quality",
            "severity": "MEDIUM",
            "component": component,
            "details": {"has_maintenance_issues": True, "issue_count": 1, "quality_issues": []},
        }

    def test_the_package_is_flagged_without_an_invented_score(self):
        vulns = [_vuln_finding(component="pkg", severity="CRITICAL", version="1.0.0")]
        rec = correlate_scorecard_with_vulnerabilities(vulns, [self._maintainer_only_finding()])[0]

        assert rec.action["packages"][0]["scorecard_score"] is None
        assert rec.affected_components == ["pkg@1.0.0 (no scorecard, UNMAINTAINED)"]

    def test_a_scored_unmaintained_package_sorts_before_an_unscored_one(self):
        vulns = [
            _vuln_finding(component="unscored", severity="CRITICAL", finding_id="v1"),
            _vuln_finding(component="scored", severity="CRITICAL", finding_id="v2"),
        ]
        quality = [
            self._maintainer_only_finding("unscored"),
            _quality_finding(component="scored", overall_score=6.0, critical_issues=["Maintained"]),
        ]
        rec = correlate_scorecard_with_vulnerabilities(vulns, quality)[0]

        assert [p["name"] for p in rec.action["packages"]] == ["scored", "unscored"]


def test_scorecard_correlation_counts_each_live_critical_and_high_cve_of_a_package():
    log4j = stored_vulnerability(
        "log4j-core",
        "2.14.0",
        [
            {"id": "CVE-2021-44228", "severity": "CRITICAL"},
            {"id": "CVE-2021-45046", "severity": "CRITICAL"},
            {"id": "CVE-2021-45105", "severity": "HIGH"},
            {"id": "CVE-2021-44832", "severity": "MEDIUM"},
            {"id": "CVE-2022-23302", "severity": "HIGH", "waived": True},
        ],
    )

    [rec] = correlate_scorecard_with_vulnerabilities(
        [log4j], [_quality_finding(component="log4j-core", critical_issues=["Maintained"])]
    )

    assert rec.description.startswith(
        "Found 3 critical/high vulnerabilities in packages with concerning OpenSSF Scorecard ratings. "
        "3 are in unmaintained packages, 0 are in packages flagged by OpenSSF Scorecard."
    )
    assert {key: rec.impact[key] for key in ("critical", "high", "medium", "total")} == {
        "critical": 2,
        "high": 1,
        "medium": 0,
        "total": 3,
    }
    assert rec.action["packages"][0]["cves_total"] == 3


def test_scorecard_correlation_counts_a_cve_on_two_installed_versions_once():
    copies = [
        stored_vulnerability("semver", version, [{"id": "CVE-2022-25883", "severity": "HIGH"}])
        for version in ("5.7.1", "7.3.5")
    ]

    [rec] = correlate_scorecard_with_vulnerabilities(copies, [_quality_finding(component="semver")])

    assert rec.description.startswith("Found 1 critical/high vulnerabilities")
    assert rec.impact["high"] == rec.impact["total"] == 1
    assert [p["version"] for p in rec.action["packages"]] == ["5.7.1", "7.3.5"]
