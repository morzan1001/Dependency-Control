"""A scan-delta that read only part of a side must say so, and must not invent changes.

Two scans holding identical findings reported 8 329 added and 8 329 removed against a live
MongoDB, because each side's unsorted fetch returned a different arbitrary window of the same
population. The window is now the same stretch of the identity space on both sides, and the
response carries what it read.
"""

import pytest

from app.services.analytics import components_delta as components_delta_module
from app.services.analytics import findings_delta as findings_delta_module
from app.services.analytics.components_delta import compare_components
from app.services.analytics.findings_delta import compare_findings

_PROJECT = "p1"
_FROM_SCAN = "scan-from"
_TO_SCAN = "scan-to"
_CAP = 4
_POPULATION = 6


def _vuln(scan_id: str, index: int) -> dict:
    """A finding whose identity is the same on both sides, so any added/removed pair is fabricated."""
    return {
        "_id": f"{scan_id}-{index}",
        "project_id": _PROJECT,
        "scan_id": scan_id,
        "finding_id": f"f-{index}",
        "type": "vulnerability",
        "severity": "HIGH",
        "component": f"lib-{index}",
        "version": "1.0.0",
        "description": f"finding {index}",
        "details": {"vulnerabilities": [{"id": f"CVE-2026-{index:05d}"}]},
    }


def _component(scan_id: str, index: int) -> dict:
    return {
        "_id": f"{scan_id}-{index}",
        "project_id": _PROJECT,
        "scan_id": scan_id,
        "name": f"lib-{index}",
        "version": "1.0.0",
        "purl": f"pkg:pypi/lib-{index}@1.0.0",
        "type": "pypi",
    }


def _seed_diverging_natural_order(collection, builder, count: int) -> None:
    """Both scans hold the same set; the collection's natural order disagrees between them, which
    is what a second scan's analyzers emitting in a different order produces."""
    for index in range(count):
        doc = builder(_FROM_SCAN, index)
        collection._docs[doc["_id"]] = doc
    for index in reversed(range(count)):
        doc = builder(_TO_SCAN, index)
        collection._docs[doc["_id"]] = doc


async def _findings_delta(db):
    return await compare_findings(
        db, project_id=_PROJECT, from_scan=_FROM_SCAN, to_scan=_TO_SCAN, severity=None, finding_type=None
    )


@pytest.mark.asyncio
async def test_identical_scans_past_the_cap_report_no_change(db, monkeypatch):
    """The measured defect: an unsorted per-side window fabricates added/removed pairs out of a
    population both scans share."""
    monkeypatch.setattr(findings_delta_module, "MAX_FETCH", _CAP)
    _seed_diverging_natural_order(db["findings"], _vuln, _POPULATION)

    resp = await _findings_delta(db)

    assert resp.totals.added == 0
    assert resp.totals.removed == 0


@pytest.mark.asyncio
async def test_a_windowed_findings_delta_reports_what_it_read(db, monkeypatch):
    monkeypatch.setattr(findings_delta_module, "MAX_FETCH", _CAP)
    _seed_diverging_natural_order(db["findings"], _vuln, _POPULATION)

    resp = await _findings_delta(db)

    assert resp.truncation is not None
    assert resp.truncation.limit == _CAP
    assert resp.truncation.from_compared == _CAP
    assert resp.truncation.from_total == _POPULATION
    assert resp.truncation.to_compared == _CAP
    assert resp.truncation.to_total == _POPULATION


@pytest.mark.asyncio
async def test_a_findings_delta_that_read_everything_reports_no_truncation(db):
    _seed_diverging_natural_order(db["findings"], _vuln, _POPULATION)

    resp = await _findings_delta(db)

    assert resp.truncation is None
    assert resp.totals.unchanged == _POPULATION


@pytest.mark.asyncio
async def test_a_windowed_components_delta_reports_what_it_read(db, monkeypatch):
    monkeypatch.setattr(components_delta_module, "MAX_FETCH", _CAP)
    _seed_diverging_natural_order(db["dependencies"], _component, _POPULATION)

    resp = await compare_components(db, project_id=_PROJECT, from_scan=_FROM_SCAN, to_scan=_TO_SCAN)

    assert resp.totals.added == 0
    assert resp.totals.removed == 0
    assert resp.truncation is not None
    assert resp.truncation.from_compared == _CAP
    assert resp.truncation.from_total == _POPULATION


_PARTIALLY_WAIVED = 3


@pytest.mark.asyncio
async def test_a_partially_waived_record_counts_once_in_the_coverage(db, monkeypatch):
    """Such a record is in both the live and the waiver-touched read; counting it twice claims rows the scan does not hold."""
    monkeypatch.setattr(findings_delta_module, "MAX_FETCH", _CAP)
    _seed_diverging_natural_order(db["findings"], _vuln, _POPULATION)
    for doc in db["findings"]._docs.values():
        if int(doc["_id"].rsplit("-", 1)[1]) < _PARTIALLY_WAIVED:
            doc["waived"] = False
            doc["details"]["vulnerabilities"].append({"id": "CVE-2026-99999", "waived": True})

    resp = await _findings_delta(db)

    assert resp.truncation is not None
    assert (resp.truncation.from_compared, resp.truncation.from_total) == (_CAP, _POPULATION)
    assert (resp.truncation.to_compared, resp.truncation.to_total) == (_CAP, _POPULATION)
    assert resp.from_waived_excluded == _PARTIALLY_WAIVED


@pytest.mark.asyncio
async def test_a_delta_under_the_cap_runs_no_count(db, monkeypatch):
    """Below the cap every total is the length of what was read, so a count is a wasted pass over the scan."""
    _seed_diverging_natural_order(db["findings"], _vuln, _POPULATION)
    counted: list[dict] = []
    findings = db["findings"]
    original_count = findings.count_documents

    async def spy_count(query, *args, **kwargs):
        counted.append(query)
        return await original_count(query, *args, **kwargs)

    monkeypatch.setattr(findings, "count_documents", spy_count)

    await _findings_delta(db)

    assert counted == []
