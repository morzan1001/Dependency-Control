"""KEV aggregation in vulnerability search must read the PERSISTED finding detail
keys (in_kev / kev_ransomware_use) written by the enrichment service — not the
never-written kev / kev_ransomware keys (improvement audit #1)."""

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
