"""Vulnerability-search CVSS sort and read must target the aggregated stored shape,
where CVSS lives per CVE in details.vulnerabilities[].cvss_score."""

from types import SimpleNamespace

from app.api.v1.endpoints.analytics.search import (
    _VULN_SORT_FIELD_MAP,
    _build_direct_vuln_result,
)


def _resolve_sort_values(doc, path: str) -> list:
    """Resolve a dotted Mongo sort path with array fan-out, as the server's sort key extraction does."""
    values = [doc]
    for part in path.split("."):
        fanned = []
        for value in values:
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict) and part in item:
                    fanned.append(item[part])
        values = fanned
    flat = []
    for value in values:
        flat.extend(value if isinstance(value, list) else [value])
    return flat


def _stored_details() -> dict:
    return {
        "fixed_version": "4.17.21",
        "vulnerabilities": [
            {"id": "CVE-2021-1", "severity": "HIGH", "cvss_score": 7.5},
            {"id": "CVE-2021-2", "severity": "CRITICAL", "cvss_score": 9.8},
        ],
    }


def test_cvss_sort_field_resolves_on_stored_shape():
    doc = {"type": "vulnerability", "component": "lodash", "details": _stored_details()}
    values = _resolve_sort_values(doc, _VULN_SORT_FIELD_MAP["cvss"])
    assert values, "the cvss sort key must exist on the aggregated stored document"
    assert 9.8 in values


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
    result = _build_direct_vuln_result(finding, _stored_details(), False, False, None, {"p1": "P1"})
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
    result = _build_direct_vuln_result(finding, details, False, False, None, {"p1": "P1"})
    assert result.cvss_score is None
