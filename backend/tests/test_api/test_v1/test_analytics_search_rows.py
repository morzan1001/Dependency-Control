"""Each vulnerability search row describes its own advisory, not the document it sits in."""

from types import SimpleNamespace

from app.api.v1.endpoints.analytics.search import _vuln_results_for_finding


def _finding(details):
    return SimpleNamespace(
        finding_id="libssl3:3.0.9-1",
        aliases=[],
        severity="CRITICAL",
        component="libssl3",
        version="3.0.9-1",
        project_id="proj-1",
        scan_id="scan-1",
        type="vulnerability",
        description="",
        waived=False,
        waiver_reason=None,
        details=details,
    )


def _rows(details, query="cve-", has_fix=None):
    return {r.vulnerability_id: r for r in _vuln_results_for_finding(_finding(details), query, None, has_fix, {})}


def test_an_unfixed_cve_row_does_not_borrow_the_documents_fix():
    rows = _rows(
        {
            "fixed_version": "3.0.11-1~deb12u2",
            "vulnerabilities": [
                {"id": "CVE-A", "severity": "CRITICAL"},
                {"id": "CVE-B", "severity": "LOW", "fixed_version": "3.0.11-1~deb12u2"},
            ],
        }
    )
    assert rows["CVE-A"].fixed_version is None
    assert rows["CVE-B"].fixed_version == "3.0.11-1~deb12u2"


def test_a_record_counts_as_fixable_when_one_of_its_advisories_has_a_fix():
    details = {"vulnerabilities": [{"id": "CVE-A"}, {"id": "CVE-B", "fixed_version": "2.0"}]}
    assert set(_rows(details, has_fix=True)) == {"CVE-A", "CVE-B"}
    assert _rows(details, has_fix=False) == {}


def test_a_ghsa_row_is_labelled_with_its_resolved_cve():
    rows = _rows({"vulnerabilities": [{"id": "GHSA-9f52-rjqv-25qv", "resolved_cve": "CVE-2026-41852"}]}, query="ghsa")
    assert list(rows) == ["CVE-2026-41852"]
