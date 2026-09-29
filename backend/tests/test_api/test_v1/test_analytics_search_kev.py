"""Vulnerability search reads the KEV roll-up enrichment persists (in_kev / kev_ransomware_use / kev_due_date)."""

from types import SimpleNamespace

from app.api.v1.endpoints.analytics.search import _vuln_results_for_finding


def _finding(details):
    return SimpleNamespace(
        finding_id="log4j-core:2.14.1",
        aliases=[],
        severity="CRITICAL",
        component="log4j-core",
        version="2.14.1",
        project_id="proj-1",
        scan_id="scan-1",
        type="vulnerability",
        description="",
        waived=False,
        waiver_reason=None,
        details=details,
    )


_KEV_DETAILS = {
    "in_kev": True,
    "kev_ransomware_use": True,
    "kev_due_date": "2026-03-01",
    "vulnerabilities": [{"id": "CVE-2021-44228"}],
}


def test_the_document_row_carries_the_persisted_kev_roll_up():
    [row] = _vuln_results_for_finding(_finding(_KEV_DETAILS), "log4j", None, None, {})

    assert (row.in_kev, row.kev_ransomware, row.kev_due_date) == (True, True, "2026-03-01")


def test_the_kev_filter_reads_the_persisted_roll_up():
    assert _vuln_results_for_finding(_finding(_KEV_DETAILS), "log4j", False, None, {}) == []
    assert _vuln_results_for_finding(_finding({"vulnerabilities": []}), "log4j", True, None, {}) == []


def test_a_document_without_kev_marks_is_not_in_kev():
    [row] = _vuln_results_for_finding(_finding({"vulnerabilities": []}), "log4j", None, None, {})

    assert (row.in_kev, row.kev_ransomware, row.kev_due_date) == (False, False, None)
