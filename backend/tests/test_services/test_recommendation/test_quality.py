"""Tests for app.services.recommendation.quality."""

from app.core.constants import SCORECARD_LOW_THRESHOLD
from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.quality import process_quality


def _quality(
    severity="MEDIUM",
    component="old-lib",
    version="1.0",
    overall_score=2.5,
    critical_issues=None,
    failed_checks=None,
    project_url="https://github.com/example/old-lib",
    finding_id="q1",
):
    return {
        "type": "quality",
        "severity": severity,
        "component": component,
        "version": version,
        "details": {
            "overall_score": overall_score,
            "critical_issues": critical_issues if critical_issues is not None else [],
            "failed_checks": failed_checks if failed_checks is not None else [],
            "project_url": project_url,
        },
        "id": finding_id,
    }


class TestProcessQualityEmpty:
    """Edge case: no findings."""

    def test_empty_list_returns_empty(self):
        assert process_quality([]) == []

    def test_empty_iterable(self):
        assert process_quality(list()) == []


class TestProcessQualityUnmaintained:
    """Unmaintained package produces SUPPLY_CHAIN_RISK recommendation."""

    def test_returns_recommendation(self):
        finding = _quality(critical_issues=["Maintained"])
        result = process_quality([finding])
        assert len(result) >= 1

    def test_type_is_supply_chain_risk(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [
            r for r in recs if "Unmaintained" in r.title
        ]
        assert len(unmaintained_rec) == 1
        assert unmaintained_rec[0].type == RecommendationType.SUPPLY_CHAIN_RISK

    def test_priority_is_high(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert unmaintained_rec.priority == Priority.HIGH

    def test_title_contains_replace_unmaintained(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert unmaintained_rec.title == "Replace Unmaintained Dependencies"

    def test_affected_components(self):
        finding = _quality(component="old-lib", critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert "old-lib" in unmaintained_rec.affected_components

    def test_multiple_unmaintained(self):
        findings = [
            _quality(
                component=f"lib-{i}",
                critical_issues=["Maintained"],
                finding_id=f"q{i}",
            )
            for i in range(3)
        ]
        recs = process_quality(findings)
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert unmaintained_rec.impact["total"] == 3

    def test_effort_is_high(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert unmaintained_rec.effort == "high"

    def test_description_mentions_count(self):
        findings = [
            _quality(
                component=f"lib-{i}",
                critical_issues=["Maintained"],
                finding_id=f"q{i}",
            )
            for i in range(2)
        ]
        recs = process_quality(findings)
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert "2" in unmaintained_rec.description


class TestProcessQualityVulnerabilities:
    """Vulnerabilities critical issue produces separate recommendation."""

    def test_vulnerabilities_issue_produces_recommendation(self):
        finding = _quality(
            critical_issues=["Vulnerabilities"],
            overall_score=5.0,
        )
        recs = process_quality([finding])
        vuln_recs = [r for r in recs if "Vulnerability" in r.title]
        assert len(vuln_recs) == 1

    def test_vulnerabilities_recommendation_type(self):
        finding = _quality(critical_issues=["Vulnerabilities"])
        recs = process_quality([finding])
        vuln_recs = [r for r in recs if "Vulnerability" in r.title]
        assert vuln_recs[0].type == RecommendationType.SUPPLY_CHAIN_RISK

    def test_vulnerabilities_priority_is_high(self):
        finding = _quality(critical_issues=["Vulnerabilities"])
        recs = process_quality([finding])
        vuln_recs = [r for r in recs if "Vulnerability" in r.title]
        assert vuln_recs[0].priority == Priority.HIGH

    def test_vulnerabilities_effort_is_medium(self):
        finding = _quality(critical_issues=["Vulnerabilities"])
        recs = process_quality([finding])
        vuln_recs = [r for r in recs if "Vulnerability" in r.title]
        assert vuln_recs[0].effort == "medium"

    def test_vulnerabilities_affected_components(self):
        finding = _quality(
            component="vuln-lib",
            critical_issues=["Vulnerabilities"],
        )
        recs = process_quality([finding])
        vuln_recs = [r for r in recs if "Vulnerability" in r.title]
        assert "vuln-lib" in vuln_recs[0].affected_components


class TestProcessQualityLowScorecard:
    """Low scorecard without unmaintained generates 'Review Low-Quality'."""

    def test_low_score_generates_review_recommendation(self):
        finding = _quality(overall_score=2.0)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 1

    def test_low_score_priority_is_medium(self):
        finding = _quality(overall_score=2.0)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert low_recs[0].priority == Priority.MEDIUM

    def test_low_score_title(self):
        finding = _quality(overall_score=2.0)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert low_recs[0].title == "Review Low-Quality Dependencies"

    def test_score_exactly_at_threshold_not_flagged(self):
        """Score exactly at SCORECARD_LOW_THRESHOLD is NOT below it."""
        finding = _quality(overall_score=SCORECARD_LOW_THRESHOLD)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 0

    def test_score_just_below_threshold_flagged(self):
        finding = _quality(overall_score=SCORECARD_LOW_THRESHOLD - 0.1)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 1

    def test_description_mentions_threshold(self):
        finding = _quality(overall_score=2.0)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert str(SCORECARD_LOW_THRESHOLD) in low_recs[0].description

    def test_impact_contains_average_score(self):
        findings = [
            _quality(overall_score=2.0, finding_id="q1"),
            _quality(overall_score=3.0, finding_id="q2"),
        ]
        recs = process_quality(findings)
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert low_recs[0].impact["average_score"] == 2.5


class TestProcessQualityLowScoreWithUnmaintained:
    """Low scorecard WITH unmaintained should NOT generate 'Review Low-Quality'."""

    def test_no_low_quality_when_unmaintained_present(self):
        finding = _quality(
            overall_score=2.0,
            critical_issues=["Maintained"],
        )
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 0

    def test_unmaintained_still_generated(self):
        finding = _quality(
            overall_score=2.0,
            critical_issues=["Maintained"],
        )
        recs = process_quality([finding])
        unmaintained_recs = [r for r in recs if "Unmaintained" in r.title]
        assert len(unmaintained_recs) == 1

    def test_multiple_with_mixed_unmaintained(self):
        """If ANY finding is unmaintained, low-quality rec is suppressed."""
        findings = [
            _quality(
                overall_score=2.0,
                critical_issues=["Maintained"],
                finding_id="q1",
            ),
            _quality(
                overall_score=3.0,
                critical_issues=[],
                finding_id="q2",
            ),
        ]
        recs = process_quality(findings)
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 0


class TestProcessQualityCodeReview:
    """Code-Review failed check produces specific recommendation."""

    def test_code_review_check_generates_recommendation(self):
        finding = _quality(
            overall_score=5.0,
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        cr_recs = [r for r in recs if "Code Review" in r.title]
        assert len(cr_recs) == 1

    def test_code_review_title(self):
        finding = _quality(
            overall_score=5.0,
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        cr_recs = [r for r in recs if "Code Review" in r.title]
        assert cr_recs[0].title == "Dependencies with Limited Code Review"

    def test_code_review_priority_is_low(self):
        finding = _quality(
            overall_score=5.0,
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        cr_recs = [r for r in recs if "Code Review" in r.title]
        assert cr_recs[0].priority == Priority.LOW

    def test_code_review_effort_is_low(self):
        finding = _quality(
            overall_score=5.0,
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        cr_recs = [r for r in recs if "Code Review" in r.title]
        assert cr_recs[0].effort == "low"

    def test_code_review_affected_components(self):
        finding = _quality(
            component="no-review-lib",
            overall_score=5.0,
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        cr_recs = [r for r in recs if "Code Review" in r.title]
        assert "no-review-lib" in cr_recs[0].affected_components

    def test_multiple_code_review_failures(self):
        findings = [
            _quality(
                component=f"lib-{i}",
                overall_score=5.0,
                failed_checks=[{"name": "Code-Review"}],
                finding_id=f"q{i}",
            )
            for i in range(3)
        ]
        recs = process_quality(findings)
        cr_recs = [r for r in recs if "Code Review" in r.title]
        assert cr_recs[0].impact["total"] == 3


class TestProcessQualityScoreNone:
    """overall_score None defaults to 0.0."""

    def test_none_score_treated_as_zero(self):
        finding = _quality(overall_score=None)
        # With score 0.0, it's below threshold, so should appear in low_score_packages
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 1

    def test_none_score_in_packages_action(self):
        finding = _quality(overall_score=None)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        packages = low_recs[0].action["packages"]
        assert packages[0]["score"] == 0.0


class TestProcessQualityHighScore:
    """Packages with good scores should not generate low-quality recs."""

    def test_high_score_no_low_quality_rec(self):
        finding = _quality(overall_score=8.0)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 0

    def test_high_score_no_unmaintained_rec(self):
        finding = _quality(overall_score=8.0)
        recs = process_quality([finding])
        unmaintained_recs = [r for r in recs if "Unmaintained" in r.title]
        assert len(unmaintained_recs) == 0

    def test_high_score_no_recommendations(self):
        finding = _quality(overall_score=8.0)
        recs = process_quality([finding])
        assert recs == []


class TestProcessQualityCombinedScenarios:
    """Complex scenarios with multiple issue types."""

    def test_unmaintained_and_vulnerabilities(self):
        finding = _quality(
            critical_issues=["Maintained", "Vulnerabilities"],
        )
        recs = process_quality([finding])
        titles = {r.title for r in recs}
        assert "Replace Unmaintained Dependencies" in titles
        assert "Address Packages with Known Vulnerability Issues" in titles

    def test_unmaintained_plus_code_review(self):
        finding = _quality(
            overall_score=2.0,
            critical_issues=["Maintained"],
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        titles = {r.title for r in recs}
        assert "Replace Unmaintained Dependencies" in titles
        assert "Dependencies with Limited Code Review" in titles
        # Low-quality suppressed because unmaintained is present
        assert "Review Low-Quality Dependencies" not in titles

    def test_all_issue_types_without_unmaintained(self):
        finding = _quality(
            overall_score=2.0,
            critical_issues=["Vulnerabilities"],
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        titles = {r.title for r in recs}
        assert "Review Low-Quality Dependencies" in titles
        assert "Address Packages with Known Vulnerability Issues" in titles
        assert "Dependencies with Limited Code Review" in titles

    def test_failed_check_as_string(self):
        """Failed checks can be plain strings instead of dicts."""
        finding = _quality(
            overall_score=5.0,
            failed_checks=["Code-Review"],
        )
        recs = process_quality([finding])
        cr_recs = [r for r in recs if "Code Review" in r.title]
        assert len(cr_recs) == 1

    def test_multiple_findings_mixed(self):
        findings = [
            _quality(
                component="unmaint-lib",
                overall_score=1.0,
                critical_issues=["Maintained"],
                finding_id="q1",
            ),
            _quality(
                component="vuln-lib",
                overall_score=5.0,
                critical_issues=["Vulnerabilities"],
                finding_id="q2",
            ),
            _quality(
                component="ok-lib",
                overall_score=8.0,
                finding_id="q3",
            ),
        ]
        recs = process_quality(findings)
        titles = {r.title for r in recs}
        assert "Replace Unmaintained Dependencies" in titles
        assert "Address Packages with Known Vulnerability Issues" in titles


class TestProcessQualityActionStructure:
    """Verify action dict content for each recommendation type."""

    def test_unmaintained_action_type(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert unmaintained_rec.action["type"] == "replace_unmaintained"

    def test_unmaintained_action_has_steps(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        assert len(unmaintained_rec.action["steps"]) > 0

    def test_unmaintained_action_packages(self):
        finding = _quality(
            component="old-lib",
            overall_score=2.5,
            critical_issues=["Maintained"],
        )
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title][0]
        packages = unmaintained_rec.action["packages"]
        assert len(packages) >= 1
        assert packages[0]["name"] == "old-lib"
        assert packages[0]["score"] == 2.5

    def test_vulnerabilities_action_type(self):
        finding = _quality(critical_issues=["Vulnerabilities"])
        recs = process_quality([finding])
        vuln_rec = [r for r in recs if "Vulnerability" in r.title][0]
        assert vuln_rec.action["type"] == "fix_scorecard_vulnerabilities"

    def test_low_quality_action_type(self):
        finding = _quality(overall_score=2.0)
        recs = process_quality([finding])
        low_rec = [r for r in recs if "Low-Quality" in r.title][0]
        assert low_rec.action["type"] == "review_quality"

    def test_low_quality_packages_sorted_by_score(self):
        findings = [
            _quality(component="lib-a", overall_score=3.0, finding_id="q1"),
            _quality(component="lib-b", overall_score=1.0, finding_id="q2"),
            _quality(component="lib-c", overall_score=2.0, finding_id="q3"),
        ]
        recs = process_quality(findings)
        low_rec = [r for r in recs if "Low-Quality" in r.title][0]
        scores = [p["score"] for p in low_rec.action["packages"]]
        assert scores == sorted(scores)

    def test_code_review_action_type(self):
        finding = _quality(
            overall_score=5.0,
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        cr_rec = [r for r in recs if "Code Review" in r.title][0]
        assert cr_rec.action["type"] == "code_review_concern"
