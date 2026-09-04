"""A scan-delta that read only part of a side must say so, and must not invent changes.

Two scans holding identical findings reported 8 329 added and 8 329 removed against a live
MongoDB, because each side's unsorted fetch returned a different arbitrary window of the same
population. The window is now the same stretch of the identity space on both sides, and the
response carries what it read.
"""

import pytest

from app.services.analytics import components_delta as components_delta_module
from app.services.analytics import findings_delta as findings_delta_module
from app.services.analytics.components_delta import compute_components_delta
from app.services.analytics.findings_delta import compute_findings_delta

_PROJECT = "p1"
_FROM_SCAN = "scan-from"
_TO_SCAN = "scan-to"
_CAP = 4
_POPULATION = 6
_PAGE = 1
_PAGE_SIZE = 50
_NO_CHANGE_FILTER = None


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
    return await compute_findings_delta(
        db,
        project_id=_PROJECT,
        from_scan=_FROM_SCAN,
        to_scan=_TO_SCAN,
        page=_PAGE,
        page_size=_PAGE_SIZE,
        change=_NO_CHANGE_FILTER,
        severity=None,
        finding_type=None,
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

    resp = await compute_components_delta(
        db,
        project_id=_PROJECT,
        from_scan=_FROM_SCAN,
        to_scan=_TO_SCAN,
        page=_PAGE,
        page_size=_PAGE_SIZE,
        change=_NO_CHANGE_FILTER,
    )

    assert resp.totals.added == 0
    assert resp.totals.removed == 0
    assert resp.truncation is not None
    assert resp.truncation.from_compared == _CAP
    assert resp.truncation.from_total == _POPULATION
