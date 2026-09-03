"""A waived finding is not a delivered risk: the delta must agree with every other metric.

Waivers are re-evaluated only for the latest scan, so the older side's flags are frozen while the
newer side is live. The bucket a finding lands in therefore depends on both sides' waiver state,
and the response has to report how many findings each side lost to the filter.
"""

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
_SECOND_WAIVED_FINDING = "f-waived-2"
_SECRET_FINDING = "f-secret"
_LOW_FINDING = "f-low"
_WAIVED_COMPONENT = "left-pad"
_LIVE_COMPONENT = "right-pad"
_SECOND_COMPONENT = "mid-pad"
_VERSION = "1.0.0"

_NOTHING = 0
_ONE = 1
_TWO = 2

# Waiver state of one side: the tri-state flag, plus the side carrying no document at all.
_WAIVED = "waived"
_NOT_WAIVED = "not-waived"
_NO_FLAG = "no-waived-key"
_NO_DOCUMENT = "no-document"


def _finding(
    fid: str,
    scan_id: str,
    *,
    component: str,
    waived: bool | None,
    finding_type: str = FindingType.VULNERABILITY.value,
    severity: str = Severity.HIGH.value,
) -> dict:
    doc: dict = {
        "_id": f"{fid}:{scan_id}",
        "finding_id": fid,
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "type": finding_type,
        "severity": severity,
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


async def _seed_side(db, scan_id: str, side: str) -> None:
    if side == _NO_DOCUMENT:
        return
    waived = {_WAIVED: True, _NOT_WAIVED: False, _NO_FLAG: None}[side]
    await db.findings.insert_one(_finding(_SHARED_FINDING, scan_id, component=_WAIVED_COMPONENT, waived=waived))


async def _delta(db, *, severity: list[str] | None = None, finding_type: list[str] | None = None):
    return await compute_findings_delta(
        db,
        project_id=_PROJECT,
        from_scan=_FROM_SCAN,
        to_scan=_TO_SCAN,
        page=_PAGE,
        page_size=_PAGE_SIZE,
        change=None,
        severity=severity,
        finding_type=finding_type,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("from_side", "to_side", "added", "removed", "unchanged"),
    [
        # A waiver live across both scans: the risk is undelivered on either side, so no bucket.
        (_WAIVED, _WAIVED, _NOTHING, _NOTHING, _NOTHING),
        # A waiver that lapsed between the two scans surfaces the finding as added.
        (_WAIVED, _NOT_WAIVED, _ONE, _NOTHING, _NOTHING),
        (_WAIVED, _NO_FLAG, _ONE, _NOTHING, _NOTHING),
        # Waiving is the decision that took the risk out of the delivered set.
        (_NOT_WAIVED, _WAIVED, _NOTHING, _ONE, _NOTHING),
        (_NO_FLAG, _WAIVED, _NOTHING, _ONE, _NOTHING),
        (_NO_DOCUMENT, _NOT_WAIVED, _ONE, _NOTHING, _NOTHING),
        (_NO_DOCUMENT, _NO_FLAG, _ONE, _NOTHING, _NOTHING),
        (_NO_DOCUMENT, _WAIVED, _NOTHING, _NOTHING, _NOTHING),
        (_NOT_WAIVED, _NO_DOCUMENT, _NOTHING, _ONE, _NOTHING),
        (_WAIVED, _NO_DOCUMENT, _NOTHING, _NOTHING, _NOTHING),
        # Documents written before the flag existed carry no ``waived`` key at all.
        (_NOT_WAIVED, _NOT_WAIVED, _NOTHING, _NOTHING, _ONE),
        (_NO_FLAG, _NO_FLAG, _NOTHING, _NOTHING, _ONE),
    ],
)
async def test_the_waiver_state_of_both_sides_decides_the_bucket(db, from_side, to_side, added, removed, unchanged):
    await _seed_side(db, _FROM_SCAN, from_side)
    await _seed_side(db, _TO_SCAN, to_side)

    result = await _delta(db)

    assert result.totals.added == added
    assert result.totals.removed == removed
    assert result.totals.unchanged == unchanged


@pytest.mark.asyncio
async def test_a_waived_finding_is_left_out_of_the_item_list(db):
    await db.findings.insert_one(_finding(_WAIVED_FINDING, _TO_SCAN, component=_WAIVED_COMPONENT, waived=True))
    await db.findings.insert_one(_finding(_LIVE_FINDING, _TO_SCAN, component=_LIVE_COMPONENT, waived=False))

    result = await _delta(db)

    assert result.totals.added == _ONE
    assert [i.finding_id for i in result.items] == [_LIVE_FINDING]


@pytest.mark.asyncio
async def test_a_lapsed_waiver_reads_as_added_and_the_response_says_how_many_were_waived_out(db):
    """The count is what lets a screen say the finding became visible because a waiver lapsed
    rather than because the code changed."""
    await db.findings.insert_one(_finding(_SHARED_FINDING, _FROM_SCAN, component=_WAIVED_COMPONENT, waived=True))
    await db.findings.insert_one(_finding(_SHARED_FINDING, _TO_SCAN, component=_WAIVED_COMPONENT, waived=False))

    result = await _delta(db)

    assert result.totals.added == _ONE
    assert result.from_waived_excluded == _ONE
    assert result.to_waived_excluded == _NOTHING


@pytest.mark.asyncio
async def test_each_side_counts_its_own_waived_findings(db):
    await db.findings.insert_one(_finding(_WAIVED_FINDING, _FROM_SCAN, component=_WAIVED_COMPONENT, waived=True))
    await db.findings.insert_one(_finding(_SECOND_WAIVED_FINDING, _FROM_SCAN, component=_SECOND_COMPONENT, waived=True))
    await db.findings.insert_one(_finding(_LIVE_FINDING, _FROM_SCAN, component=_LIVE_COMPONENT, waived=False))
    await db.findings.insert_one(_finding(_WAIVED_FINDING, _TO_SCAN, component=_WAIVED_COMPONENT, waived=True))

    result = await _delta(db)

    assert result.from_waived_excluded == _TWO
    assert result.to_waived_excluded == _ONE


@pytest.mark.asyncio
async def test_a_side_with_no_waivers_reports_nothing_excluded(db):
    await db.findings.insert_one(_finding(_LIVE_FINDING, _FROM_SCAN, component=_LIVE_COMPONENT, waived=False))
    await db.findings.insert_one(_finding(_LIVE_FINDING, _TO_SCAN, component=_LIVE_COMPONENT, waived=None))

    result = await _delta(db)

    assert result.from_waived_excluded == _NOTHING
    assert result.to_waived_excluded == _NOTHING


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filters",
    [
        {"finding_type": [FindingType.SECRET.value]},
        {"severity": [Severity.LOW.value]},
    ],
)
async def test_the_counts_cover_the_same_item_set_as_the_delta(db, filters):
    """Counting outside the caller's filters would describe findings the delta never looked at."""
    await db.findings.insert_one(_finding(_WAIVED_FINDING, _FROM_SCAN, component=_WAIVED_COMPONENT, waived=True))
    await db.findings.insert_one(
        _finding(
            _SECRET_FINDING,
            _FROM_SCAN,
            component=_SECOND_COMPONENT,
            waived=True,
            finding_type=FindingType.SECRET.value,
        )
    )
    await db.findings.insert_one(
        _finding(
            _LOW_FINDING,
            _FROM_SCAN,
            component=_LIVE_COMPONENT,
            waived=True,
            severity=Severity.LOW.value,
        )
    )

    result = await _delta(db, **filters)

    assert result.from_waived_excluded == _ONE
