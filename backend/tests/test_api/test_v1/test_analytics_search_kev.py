"""Vulnerability search reads the KEV roll-up enrichment persists (in_kev / kev_ransomware_use / kev_due_date)."""

from app.api.v1.endpoints.analytics.search import _row_matches, _vuln_results_for_finding
from app.models.finding_record import FindingRecord


def _finding(details):
    return FindingRecord(
        id="log4j-core:2.14.1",
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
        scanners=["trivy"],
        details=details,
    )


_KEV_DETAILS = {
    "in_kev": True,
    "kev_ransomware_use": True,
    "kev_due_date": "2026-03-01",
    "vulnerabilities": [{"id": "CVE-2021-44228"}],
}


def test_the_document_row_carries_the_persisted_kev_roll_up():
    [row] = _vuln_results_for_finding(_finding(_KEV_DETAILS), "log4j", {})

    assert (row.in_kev, row.kev_ransomware, row.kev_due_date) == (True, True, "2026-03-01")


def test_the_kev_filter_reads_the_persisted_roll_up():
    [kev_row] = _vuln_results_for_finding(_finding(_KEV_DETAILS), "log4j", {})
    [plain_row] = _vuln_results_for_finding(_finding({"vulnerabilities": []}), "log4j", {})

    assert not _row_matches(kev_row, None, False, None, False)
    assert not _row_matches(plain_row, None, True, None, False)


def test_a_document_without_kev_marks_is_not_in_kev():
    [row] = _vuln_results_for_finding(_finding({"vulnerabilities": []}), "log4j", {})

    assert (row.in_kev, row.kev_ransomware, row.kev_due_date) == (False, False, None)
