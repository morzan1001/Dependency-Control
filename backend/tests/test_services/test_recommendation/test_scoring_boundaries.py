"""The weighted sum that orders the toxic-dependency feed.

The score decides which packages reach the operator at all, and it is otherwise pinned only by
which cards appear — an ordering a single term can dominate without changing the set.
"""

import pytest

from app.core.constants import DETAILS_KEY_IN_KEV
from app.services.recommendation.risks import _append_vuln_risk_factor

_CRITICAL_WEIGHT = 50
_HIGH_WEIGHT = 20
_PER_VULNERABILITY_WEIGHT = 5
_KEV_WEIGHT = 100


def _vuln(severity: str, in_kev: bool = False) -> dict:
    return {"type": "vulnerability", "severity": severity, "details": {DETAILS_KEY_IN_KEV: in_kev}}


def _scored(vulns: list[dict]) -> dict:
    pkg: dict = {"risk_factors": [], "total_score": 0, "vulns": vulns, "version": "1.0.0"}
    _append_vuln_risk_factor(pkg)
    return pkg


@pytest.mark.parametrize(
    "vulns,expected",
    [
        ([], 0),
        ([_vuln("CRITICAL")], _CRITICAL_WEIGHT + _PER_VULNERABILITY_WEIGHT),
        ([_vuln("HIGH")], _HIGH_WEIGHT + _PER_VULNERABILITY_WEIGHT),
        ([_vuln("MEDIUM")], _PER_VULNERABILITY_WEIGHT),
        ([_vuln("HIGH", in_kev=True)], _HIGH_WEIGHT + _PER_VULNERABILITY_WEIGHT + _KEV_WEIGHT),
        (
            [_vuln("CRITICAL"), _vuln("HIGH"), _vuln("LOW")],
            _CRITICAL_WEIGHT + _HIGH_WEIGHT + 3 * _PER_VULNERABILITY_WEIGHT,
        ),
    ],
)
def test_the_risk_score_is_the_weighted_sum(vulns, expected):
    assert _scored(vulns)["total_score"] == expected


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM"])
def test_one_more_vulnerability_can_only_raise_the_score(severity):
    baseline = _scored([_vuln("LOW")])["total_score"]

    assert _scored([_vuln("LOW"), _vuln(severity)])["total_score"] > baseline


@pytest.mark.parametrize(
    "vulns,expected_severity",
    [
        ([_vuln("CRITICAL")], "CRITICAL"),
        ([_vuln("MEDIUM", in_kev=True)], "CRITICAL"),
        ([_vuln("HIGH")], "HIGH"),
        ([_vuln("MEDIUM")], "MEDIUM"),
    ],
)
def test_the_risk_factor_reports_the_worst_severity_present(vulns, expected_severity):
    assert _scored(vulns)["risk_factors"][0]["severity"] == expected_severity


def test_the_risk_factor_counts_each_severity_it_names():
    vulns = [_vuln("CRITICAL"), _vuln("CRITICAL"), _vuln("HIGH"), _vuln("LOW", in_kev=True)]

    description = _scored(vulns)["risk_factors"][0]["description"]

    assert description == "4 vulnerabilities (2 critical, 1 high, 1 KEV)"
