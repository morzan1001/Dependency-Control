"""A finding's own vulnerability-search row reads CVSS where it is stored: per CVE in details.vulnerabilities[]."""

from types import SimpleNamespace

from app.api.v1.endpoints.analytics.search import _build_direct_vuln_result


def _stored_details() -> dict:
    return {
        "fixed_version": "4.17.21",
        "vulnerabilities": [
            {"id": "CVE-2021-1", "severity": "HIGH", "cvss_score": 7.5},
            {"id": "CVE-2021-2", "severity": "CRITICAL", "cvss_score": 9.8},
        ],
    }


def test_direct_result_carries_max_nested_cvss():
    finding = SimpleNamespace(
        finding_id="lodash:4.17.11",
        aliases=[],
        severity="CRITICAL",
        component="lodash",
        version="4.17.11",
        project_id="p1",
        scan_id="s1",
        type="vulnerability",
        description="",
        waived=False,
        waiver_reason=None,
    )
    result = _build_direct_vuln_result(finding, _stored_details(), {"p1": "P1"})
    assert result.cvss_score == 9.8


def test_direct_result_cvss_none_when_no_nested_scores():
    finding = SimpleNamespace(
        finding_id="lodash:4.17.11",
        aliases=[],
        severity="LOW",
        component="lodash",
        version="4.17.11",
        project_id="p1",
        scan_id="s1",
        type="vulnerability",
        description="",
        waived=False,
        waiver_reason=None,
    )
    details = {"fixed_version": None, "vulnerabilities": [{"id": "CVE-1", "cvss_score": None}]}
    result = _build_direct_vuln_result(finding, details, {"p1": "P1"})
    assert result.cvss_score is None
