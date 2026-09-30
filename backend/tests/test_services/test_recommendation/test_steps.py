"""Every card hands the frontend its remediation as un-numbered `steps`."""

import re

import pytest

from app.services.recommendation.graph import analyze_deep_dependency_chains
from app.services.recommendation.insights import (
    analyze_cross_project_patterns,
    correlate_scorecard_with_vulnerabilities,
)
from app.services.recommendation.trends import CveRecurrence, analyze_recurring_issues
from app.services.recommendations import RecommendationEngine
from tests.test_services.test_normalizers.test_secret import _FILESYSTEM_FINDING
from tests.test_services.test_recommendation.test_engine import _EOL_ISSUE, _MALWARE_ISSUE, _produced
from tests.test_services.test_recommendation.test_graph import _chain, _dep
from tests.test_services.test_recommendation.test_insights import (
    _cross_project_data,
    _project,
    _quality_finding,
    _shared_package,
    _vuln_finding,
)

_NUMBERED = re.compile(r"^\d+\. ")


def _engine_cards():
    findings = _produced(
        os_malware={"malware_issues": [_MALWARE_ISSUE]},
        end_of_life={"eol_issues": [_EOL_ISSUE]},
        trufflehog={"findings": [_FILESYSTEM_FINDING]},
    )
    return RecommendationEngine().generate_recommendations(findings=findings)


def _graph_cards():
    cycle = [
        _dep("a", direct=True, parent_components=["pkg:npm/b@1.0"]),
        _dep("b", parent_components=["pkg:npm/a@1.0"]),
    ]
    return analyze_deep_dependency_chains(_chain(12) + cycle, max_dependency_depth=3)


def _recurring_cards():
    recurrence = {"CVE-2024-0001": CveRecurrence(scans={"s1", "s2", "s3"}, severity="CRITICAL", component="pkg")}
    return analyze_recurring_issues(recurrence, 10)


def _insight_cards():
    vulns = [_vuln_finding(component="pkg", severity="CRITICAL")]
    quality = [_quality_finding(component="pkg", overall_score=3.0, critical_issues=["Maintained"])]
    data = _cross_project_data(
        [_project(project_id="p1"), _project(project_id="p2")], shared_packages=[_shared_package()]
    )
    return correlate_scorecard_with_vulnerabilities(vulns, quality) + analyze_cross_project_patterns(data)


@pytest.mark.parametrize("cards", [_engine_cards, _graph_cards, _recurring_cards, _insight_cards])
def test_every_card_lists_un_numbered_steps(cards):
    recommendations = cards()

    assert recommendations
    for rec in recommendations:
        assert "suggestions" not in rec.action, rec.type
        for step in rec.action.get("steps", []):
            assert step, rec.type
            assert not _NUMBERED.match(step), (rec.type, step)


@pytest.mark.parametrize("cards", [_graph_cards, _recurring_cards, _insight_cards])
def test_cards_that_advise_carry_steps(cards):
    assert all(rec.action.get("steps") for rec in cards())
