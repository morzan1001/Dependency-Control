"""Each vulnerability search row describes its own advisory, not the document it sits in."""

from app.api.v1.endpoints.analytics.search import _row_matches, _vuln_results_for_finding
from app.models.finding_record import FindingRecord
from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.enrichment.service import apply_enrichments


def _finding(details):
    return FindingRecord(
        id="libssl3:3.0.9-1",
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
        scanners=["trivy"],
        details=details,
    )


def _rows(details, query="cve-", severity=None, in_kev=None, has_fix=None, include_waived=False):
    return {
        r.vulnerability_id: r
        for r in _vuln_results_for_finding(_finding(details), query, {})
        if _row_matches(r, severity, in_kev, has_fix, include_waived)
    }


def _kev_and_plain():
    """A KEV, ransomware, high-EPSS CVE and a plain sibling, enriched the way ingest stores them."""
    details = {
        "vulnerabilities": [
            {"id": "CVE-2021-0001", "severity": "CRITICAL", "fixed_version": "3.0.11"},
            {"id": "CVE-2021-0002", "severity": "LOW"},
        ]
    }
    kev = VulnerabilityEnrichment(
        cve="CVE-2021-0001",
        epss_score=0.9,
        epss_percentile=99.0,
        is_kev=True,
        kev_due_date="2022-01-01",
        kev_ransomware_use=True,
        risk_score=90.0,
    )
    apply_enrichments(details, {"CVE-2021-0001": kev})
    return details


def test_a_plain_cve_row_does_not_borrow_its_kev_siblings_threat_intel():
    row = _rows(_kev_and_plain())["CVE-2021-0002"]

    assert (row.in_kev, row.kev_ransomware, row.kev_due_date) == (False, False, None)
    assert (row.epss_score, row.epss_percentile, row.fixed_version) == (None, None, None)


def test_the_kev_filter_keeps_each_cve_by_its_own_listing():
    assert set(_rows(_kev_and_plain(), in_kev=False)) == {"CVE-2021-0002"}
    assert set(_rows(_kev_and_plain(), in_kev=True)) == {"CVE-2021-0001"}


def test_the_fix_filter_keeps_each_cve_by_its_own_fix():
    assert set(_rows(_kev_and_plain(), has_fix=True)) == {"CVE-2021-0001"}
    assert set(_rows(_kev_and_plain(), has_fix=False)) == {"CVE-2021-0002"}


def test_the_severity_filter_keeps_each_cve_by_its_own_severity():
    assert set(_rows(_kev_and_plain(), severity="low")) == {"CVE-2021-0002"}


def test_a_waived_cve_of_a_partly_waived_record_is_left_out_unless_asked_for():
    details = {"vulnerabilities": [{"id": "CVE-A", "waived": True}, {"id": "CVE-B"}]}

    assert set(_rows(details)) == {"CVE-B"}
    assert set(_rows(details, include_waived=True)) == {"CVE-A", "CVE-B"}


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


def test_a_ghsa_row_is_labelled_with_its_resolved_cve_and_keeps_the_ghsa_as_alias():
    rows = _rows({"vulnerabilities": [{"id": "GHSA-9f52-rjqv-25qv", "resolved_cve": "CVE-2026-41852"}]}, query="ghsa")

    assert list(rows) == ["CVE-2026-41852"]
    assert rows["CVE-2026-41852"].aliases == ["GHSA-9f52-rjqv-25qv"]
