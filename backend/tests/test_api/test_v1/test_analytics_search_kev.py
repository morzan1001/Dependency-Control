"""KEV aggregation in vulnerability search must read the persisted finding detail keys (in_kev / kev_ransomware_use) written by enrichment, not the never-written kev / kev_ransomware keys."""

from app.api.v1.endpoints.analytics.search import _aggregate_kev_status


def test_aggregate_kev_status_reads_persisted_finding_detail_keys():
    details = {"in_kev": True, "kev_ransomware_use": True}
    in_kev, ransomware, _due = _aggregate_kev_status(details, [])
    assert in_kev is True
    assert ransomware is True


def test_aggregate_kev_status_reads_persisted_nested_vuln_keys():
    nested = [{"id": "CVE-1", "in_kev": True, "kev_ransomware_use": True}]
    in_kev, ransomware, _due = _aggregate_kev_status({}, nested)
    assert in_kev is True
    assert ransomware is True


def test_aggregate_kev_status_false_when_absent():
    in_kev, ransomware, _due = _aggregate_kev_status({}, [])
    assert in_kev is False
    assert ransomware is False


def test_aggregate_kev_status_reports_the_earliest_nested_due_date():
    nested = [
        {"id": "CVE-1", "in_kev": True, "kev_due_date": "2026-11-30"},
        {"id": "CVE-2", "in_kev": True, "kev_due_date": "2026-03-01"},
    ]
    _in_kev, _ransomware, due = _aggregate_kev_status({}, nested)
    assert due == "2026-03-01"


def test_aggregate_kev_status_earliest_due_date_does_not_depend_on_nesting_order():
    nested = [
        {"id": "CVE-2", "in_kev": True, "kev_due_date": "2026-03-01"},
        {"id": "CVE-1", "in_kev": True, "kev_due_date": "2026-11-30"},
    ]
    _in_kev, _ransomware, due = _aggregate_kev_status({}, nested)
    assert due == "2026-03-01"


def test_aggregate_kev_status_nested_due_date_can_pull_the_finding_deadline_forward():
    nested = [{"id": "CVE-1", "in_kev": True, "kev_due_date": "2026-03-01"}]
    _in_kev, _ransomware, due = _aggregate_kev_status({"kev_due_date": "2026-11-30"}, nested)
    assert due == "2026-03-01"
