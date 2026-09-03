"""A waived finding is not a delivered risk: the delta must agree with every other metric."""

from datetime import datetime, timezone

import pytest

from app.models.finding import FindingType, Severity
from app.services.analytics.findings_delta import compute_findings_delta

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)

_PROJECT = "p1"
_FROM_SCAN = "from"
_TO_SCAN = "to"

_PAGE = 1
_PAGE_SIZE = 50

_WAIVED_FINDING = "f-waived"
_LIVE_FINDING = "f-live"
_SHARED_FINDING = "f-shared"
_WAIVED_COMPONENT = "left-pad"
_LIVE_COMPONENT = "right-pad"
_VERSION = "1.0.0"

_NOTHING = 0
_ONE = 1


def _finding(fid: str, scan_id: str, *, component: str, waived: bool | None) -> dict:
    doc: dict = {
        "_id": f"{fid}:{scan_id}",
        "finding_id": fid,
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "type": FindingType.VULNERABILITY.value,
        "severity": Severity.HIGH.value,
        "component": component,
        "version": _VERSION,
        "description": fid,
        "found_in": [],
        "details": {"vulnerabilities": [{"id": f"CVE-{fid}"}]},
        "scan_created_at": _NOW,
    }
    if waived is not None:
        doc["waived"] = waived
    return doc


async def _delta(db):
    return await compute_findings_delta(
        db,
        project_id=_PROJECT,
        from_scan=_FROM_SCAN,
        to_scan=_TO_SCAN,
        page=_PAGE,
        page_size=_PAGE_SIZE,
        change=None,
        severity=None,
        finding_type=None,
    )


@pytest.mark.asyncio
async def test_a_waived_finding_is_not_reported_as_added(db):
    await db.findings.insert_one(_finding(_WAIVED_FINDING, _TO_SCAN, component=_WAIVED_COMPONENT, waived=True))
    await db.findings.insert_one(_finding(_LIVE_FINDING, _TO_SCAN, component=_LIVE_COMPONENT, waived=False))

    result = await _delta(db)

    assert result.totals.added == _ONE
    assert [i.finding_id for i in result.items] == [_LIVE_FINDING]


@pytest.mark.asyncio
async def test_waiving_a_finding_reports_it_as_removed_from_the_newer_side(db):
    """Waiving is the decision that took the risk out of the delivered set, so the delta
    reports the drop rather than calling it unchanged."""
    await db.findings.insert_one(_finding(_SHARED_FINDING, _FROM_SCAN, component=_WAIVED_COMPONENT, waived=False))
    await db.findings.insert_one(_finding(_SHARED_FINDING, _TO_SCAN, component=_WAIVED_COMPONENT, waived=True))

    result = await _delta(db)

    assert result.totals.removed == _ONE
    assert result.totals.added == _NOTHING
    assert result.totals.unchanged == _NOTHING


@pytest.mark.asyncio
async def test_a_finding_without_the_flag_counts_as_not_waived(db):
    """Documents written before the flag existed carry no ``waived`` key at all."""
    await db.findings.insert_one(_finding(_SHARED_FINDING, _FROM_SCAN, component=_WAIVED_COMPONENT, waived=None))
    await db.findings.insert_one(_finding(_SHARED_FINDING, _TO_SCAN, component=_WAIVED_COMPONENT, waived=None))

    result = await _delta(db)

    assert result.totals.unchanged == _ONE
    assert result.totals.added == _NOTHING
    assert result.totals.removed == _NOTHING


@pytest.mark.asyncio
async def test_an_explicitly_unwaived_finding_is_unaffected(db):
    await db.findings.insert_one(_finding(_SHARED_FINDING, _FROM_SCAN, component=_WAIVED_COMPONENT, waived=False))
    await db.findings.insert_one(_finding(_SHARED_FINDING, _TO_SCAN, component=_WAIVED_COMPONENT, waived=False))

    result = await _delta(db)

    assert result.totals.unchanged == _ONE
    assert result.totals.added == _NOTHING
    assert result.totals.removed == _NOTHING
