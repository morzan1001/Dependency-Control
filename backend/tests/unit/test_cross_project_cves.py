"""Cross-project shared-CVE analysis must collect CVE ids from the aggregated
stored shape (details.vulnerabilities[].id); details.cve_id is never written."""

import asyncio

from app.api.v1.helpers.analytics import cross_project_cve_pipeline
from tests.mocks.fake_mongo import FakeCollection


def _agg_vuln_doc(_id, scan_id, cve_ids):
    return {
        "_id": _id,
        "scan_id": scan_id,
        "type": "vulnerability",
        "component": "lodash",
        "version": "4.17.20",
        "details": {
            "vulnerabilities": [{"id": c, "severity": "HIGH"} for c in cve_ids],
            "fixed_version": None,
        },
    }


def _run(col: FakeCollection, scan_ids: list[str]):
    return asyncio.run(col.aggregate(cross_project_cve_pipeline(scan_ids)).to_list())


def test_collects_cves_from_nested_vulnerability_entries():
    col = FakeCollection()
    docs = [
        _agg_vuln_doc("f1", "s1", ["CVE-2024-1", "CVE-2024-2"]),
        _agg_vuln_doc("f2", "s1", ["CVE-2024-1"]),
        _agg_vuln_doc("f3", "s2", ["CVE-2024-2"]),
    ]
    col._docs = {d["_id"]: d for d in docs}

    rows = {r["_id"]: sorted(c for c in r["cves"] if c) for r in _run(col, ["s1", "s2"])}
    assert rows["s1"] == ["CVE-2024-1", "CVE-2024-2"]
    assert rows["s2"] == ["CVE-2024-2"]


def test_ignores_non_vulnerability_findings_and_other_scans():
    col = FakeCollection()
    docs = [
        _agg_vuln_doc("f1", "s1", ["CVE-2024-1"]),
        {"_id": "f2", "scan_id": "s1", "type": "license", "details": {"license": "MIT"}},
        _agg_vuln_doc("f3", "other", ["CVE-2024-9"]),
    ]
    col._docs = {d["_id"]: d for d in docs}

    rows = {r["_id"]: r["cves"] for r in _run(col, ["s1"])}
    assert list(rows) == ["s1"]
    assert rows["s1"] == ["CVE-2024-1"]


def test_finding_without_nested_entries_contributes_nothing():
    col = FakeCollection()
    doc = _agg_vuln_doc("f1", "s1", [])
    col._docs = {doc["_id"]: doc}

    assert _run(col, ["s1"]) == []
