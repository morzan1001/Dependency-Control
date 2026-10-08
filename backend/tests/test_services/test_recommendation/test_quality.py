"""Tests for app.services.recommendation.quality."""

from app.core.constants import SCORECARD_POOR_QUALITY_THRESHOLD
from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation import quality
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
    has_maintenance_issues=None,
):
    critical = critical_issues if critical_issues is not None else []
    # Mirrors the stored aggregated shape: per-issue scorecard fields live one
    # level down in quality_issues[].details, only the roll-ups sit at the top.
    return {
        "type": "quality",
        "severity": severity,
        "component": component,
        "version": version,
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
                    "severity": severity,
                    "details": {
                        "overall_score": overall_score,
                        "critical_issues": critical,
                        "failed_checks": failed_checks if failed_checks is not None else [],
                        "project_url": project_url,
                    },
                }
            ],
        },
        "id": finding_id,
    }


class TestProcessQualityMaintenanceFlag:
    def test_only_the_aggregated_flag_marks_a_package_unmaintained(self):
        finding = _quality(overall_score=None, critical_issues=["Maintained"], has_maintenance_issues=False)
        recs = process_quality([finding])
        assert not [r for r in recs if "Unmaintained" in r.title]


class TestProcessQualityEmpty:
    def test_empty_list_returns_empty(self):
        assert process_quality([]) == []


class TestProcessQualityUnmaintained:
    def test_returns_recommendation(self):
        finding = _quality(critical_issues=["Maintained"])
        result = process_quality([finding])
        assert len(result) >= 1

    def test_type_is_supply_chain_risk(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = [r for r in recs if "Unmaintained" in r.title]
        assert len(unmaintained_rec) == 1
        assert unmaintained_rec[0].type == RecommendationType.SUPPLY_CHAIN_RISK

    def test_priority_is_high(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
        assert unmaintained_rec.priority == Priority.HIGH

    def test_title_contains_replace_unmaintained(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
        assert unmaintained_rec.title == "Replace Unmaintained Dependencies"

    def test_affected_components(self):
        finding = _quality(component="old-lib", critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
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
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
        assert unmaintained_rec.impact == {"total": 0}
        assert unmaintained_rec.affected_components_total == 3

    def test_effort_is_high(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
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
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
        assert "2" in unmaintained_rec.description


class TestProcessQualityVulnerabilities:
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
        """Score exactly at SCORECARD_POOR_QUALITY_THRESHOLD is NOT below it."""
        finding = _quality(overall_score=SCORECARD_POOR_QUALITY_THRESHOLD)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 0

    def test_score_just_below_threshold_flagged(self):
        finding = _quality(overall_score=SCORECARD_POOR_QUALITY_THRESHOLD - 0.1)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert len(low_recs) == 1

    def test_description_mentions_threshold(self):
        finding = _quality(overall_score=2.0)
        recs = process_quality([finding])
        low_recs = [r for r in recs if "Low-Quality" in r.title]
        assert str(SCORECARD_POOR_QUALITY_THRESHOLD) in low_recs[0].description


class TestProcessQualityLowScoreWithUnmaintained:
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
        """A package the unmaintained card names is not listed again as low-quality."""
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
        assert cr_recs[0].impact == {"total": 0}
        assert cr_recs[0].affected_components_total == 3


class TestProcessQualityHighScore:
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
    def test_unmaintained_action_type(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
        assert unmaintained_rec.action["type"] == "replace_unmaintained"

    def test_unmaintained_action_has_steps(self):
        finding = _quality(critical_issues=["Maintained"])
        recs = process_quality([finding])
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
        assert len(unmaintained_rec.action["steps"]) > 0

    def test_unmaintained_action_packages(self):
        finding = _quality(
            component="old-lib",
            overall_score=2.5,
            critical_issues=["Maintained"],
        )
        recs = process_quality([finding])
        unmaintained_rec = next(r for r in recs if "Unmaintained" in r.title)
        packages = unmaintained_rec.action["packages"]
        assert len(packages) >= 1
        assert packages[0]["name"] == "old-lib"
        assert packages[0]["score"] == 2.5

    def test_vulnerabilities_action_type(self):
        finding = _quality(critical_issues=["Vulnerabilities"])
        recs = process_quality([finding])
        vuln_rec = next(r for r in recs if "Vulnerability" in r.title)
        assert vuln_rec.action["type"] == "fix_scorecard_vulnerabilities"

    def test_low_quality_action_type(self):
        finding = _quality(overall_score=2.0)
        recs = process_quality([finding])
        low_rec = next(r for r in recs if "Low-Quality" in r.title)
        assert low_rec.action["type"] == "review_quality"

    def test_low_quality_packages_sorted_by_score(self):
        findings = [
            _quality(component="lib-a", overall_score=3.0, finding_id="q1"),
            _quality(component="lib-b", overall_score=1.0, finding_id="q2"),
            _quality(component="lib-c", overall_score=2.0, finding_id="q3"),
        ]
        recs = process_quality(findings)
        low_rec = next(r for r in recs if "Low-Quality" in r.title)
        scores = [p["score"] for p in low_rec.action["packages"]]
        assert scores == sorted(scores)

    def test_code_review_action_type(self):
        finding = _quality(
            overall_score=5.0,
            failed_checks=[{"name": "Code-Review"}],
        )
        recs = process_quality([finding])
        cr_rec = next(r for r in recs if "Code Review" in r.title)
        assert cr_rec.action["type"] == "code_review_concern"


class TestQualityActionsNameHowManyPackagesTheySampled:
    def _action(self, action_type, **kwargs):
        population = quality._PACKAGES_SAMPLED + 2
        findings = [
            _quality(component=f"lib-{i:02d}", overall_score=float(i % 4), finding_id=f"q{i}", **kwargs)
            for i in range(population)
        ]
        action = next(r for r in process_quality(findings) if r.action["type"] == action_type).action
        return action, population

    def test_the_unmaintained_action(self):
        action, population = self._action("replace_unmaintained", critical_issues=["Maintained"])

        assert len(action["packages"]) == quality._PACKAGES_SAMPLED
        assert action["packages_total"] == population

    def test_the_low_score_action(self):
        action, population = self._action("review_quality")

        assert len(action["packages"]) == quality._PACKAGES_SAMPLED
        assert action["packages_total"] == population
        assert action["packages"][0]["score"] == 0.0


class TestUnmaintainedFromMaintenanceRollup:
    def test_has_maintenance_issues_alone_triggers_unmaintained(self):
        """maintainer_risk aggregates carry no scorecard entry, only the has_maintenance_issues roll-up."""
        finding = {
            "type": "quality",
            "severity": "MEDIUM",
            "component": "stale-lib",
            "version": "1.0",
            "details": {
                "overall_score": None,
                "has_maintenance_issues": True,
                "issue_count": 1,
                "quality_issues": [
                    {
                        "id": "MAINT-stale-lib",
                        "type": "maintainer_risk",
                        "details": {"risks": [{"type": "stale_package"}]},
                    }
                ],
            },
            "id": "q-maint",
        }
        recs = process_quality([finding])
        assert any(r.title == "Replace Unmaintained Dependencies" for r in recs)


class TestQualityCardsCountPackagesNotVersions:
    def _versions(self, **kwargs):
        return [
            _quality(version=version, finding_id=f"q{n}", **{**kwargs, "overall_score": score})
            for n, (version, score) in enumerate((("1.0", 4.0), ("2.0", 2.0), ("3.0", 3.0)))
        ]

    def test_an_unmaintained_package_at_three_versions_is_one_package(self):
        [rec] = [
            r for r in process_quality(self._versions(critical_issues=["Maintained"])) if "Unmaintained" in r.title
        ]

        assert rec.description.startswith("Found 1 potentially unmaintained packages.")
        assert rec.affected_components_total == 1
        assert rec.action["packages"] == [
            {"name": "old-lib", "score": 2.0, "url": "https://github.com/example/old-lib"}
        ]

    def test_a_low_quality_package_at_three_versions_is_one_package(self):
        [rec] = [r for r in process_quality(self._versions()) if "Low-Quality" in r.title]

        assert rec.description.startswith("Found 1 packages with OpenSSF Scorecard")
        assert rec.impact == {"total": 0}
        assert rec.affected_components_total == 1
        assert rec.action["packages"] == [{"name": "old-lib", "score": 2.0, "issues": []}]

    def test_a_vulnerable_package_at_three_versions_is_one_package(self):
        [rec] = [
            r
            for r in process_quality(self._versions(critical_issues=["Vulnerabilities"]))
            if "Vulnerability" in r.title
        ]

        assert rec.description.startswith("1 packages have unaddressed security vulnerabilities")
        assert rec.impact == {"total": 0}
        assert rec.affected_components_total == 1

    def test_an_unmaintained_package_keeps_its_score_beside_an_unscored_version(self):
        findings = [
            _quality(version=version, finding_id=version, overall_score=score, has_maintenance_issues=True)
            for version, score in (("1.0", None), ("2.0", 3.0), ("3.0", None))
        ]

        [rec] = [r for r in process_quality(findings) if "Unmaintained" in r.title]

        assert [p["score"] for p in rec.action["packages"]] == [3.0]


def test_a_maintainer_risk_finding_without_a_scorecard_is_not_listed_as_low_score():
    finding = {"type": "quality", "severity": "MEDIUM", "component": "pkg", "version": "1.0", "details": {}}

    assert process_quality([finding]) == []


def test_an_unrelated_unmaintained_package_leaves_the_low_score_card_in_place():
    low_scores = [_quality(component=f"lowscore-{n}", overall_score=2.0, finding_id=f"q{n}") for n in range(5)]
    stale = _quality(component="stale-pkg", overall_score=None, has_maintenance_issues=True, finding_id="q-stale")

    recs = {r.title: r for r in process_quality([*low_scores, stale])}

    assert recs["Replace Unmaintained Dependencies"].affected_components == ["stale-pkg"]
    assert recs["Review Low-Quality Dependencies"].affected_components == [f"lowscore-{n}" for n in range(5)]
