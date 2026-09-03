"""A rescan loses its callgraph, so a release side can be reachability-empty against an enriched
HEAD. The response has to say so per side, or adjusted_risk_score reads as comparable."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.services.analytics.scan_delta import compute_scan_delta_dispatch

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)

_PROJECT = "p1"
_BRANCH = "main"
_RELEASE_SCAN = "released-scan"
_HEAD_SCAN = "head-scan"

_FINDINGS = "findings"
_COMPONENTS = "components"
_CRYPTO = "crypto"
_EVERY_CATEGORY = [_FINDINGS, _COMPONENTS, _CRYPTO]

_PAGE = 1
_PAGE_SIZE = 50

_COVERABLE = 40
_NONE_ANALYSED = 0
_MOST_ANALYSED = 37
_UNREPORTED = 0


def _scan(scan_id: str, reachability: dict | None = None) -> dict:
    doc: dict = {
        "_id": scan_id,
        "project_id": _PROJECT,
        "branch": _BRANCH,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": _NOW,
    }
    if reachability is not None:
        doc["stats"] = {"reachability": reachability}
    return doc


async def _dispatch(db, category: str = _FINDINGS):
    return await compute_scan_delta_dispatch(
        db=db,
        project_id=_PROJECT,
        category=category,
        from_scan=_RELEASE_SCAN,
        to_scan=_HEAD_SCAN,
        page=_PAGE,
        page_size=_PAGE_SIZE,
        change=None,
        severity=None,
        finding_type=None,
        allow_same_scan=False,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("category", _EVERY_CATEGORY)
async def test_every_category_labels_both_sides(db, category):
    """A label present on one category and absent on the others cannot be read: the caller
    could not tell "no coverage data" from "this category does not report it"."""
    await db.scans.insert_one(_scan(_RELEASE_SCAN, {"coverable_count": _COVERABLE, "analyzed_count": _NONE_ANALYSED}))
    await db.scans.insert_one(_scan(_HEAD_SCAN, {"coverable_count": _COVERABLE, "analyzed_count": _MOST_ANALYSED}))

    result = await _dispatch(db, category)

    assert result.from_reachability is not None
    assert result.from_reachability.coverable_count == _COVERABLE
    assert result.from_reachability.analyzed_count == _NONE_ANALYSED
    assert result.to_reachability is not None
    assert result.to_reachability.coverable_count == _COVERABLE
    assert result.to_reachability.analyzed_count == _MOST_ANALYSED


@pytest.mark.asyncio
async def test_a_scan_without_reachability_stats_reports_no_label(db):
    await db.scans.insert_one(_scan(_RELEASE_SCAN))
    await db.scans.insert_one(_scan(_HEAD_SCAN, {"coverable_count": _COVERABLE, "analyzed_count": _MOST_ANALYSED}))

    result = await _dispatch(db)

    assert result.from_reachability is None
    assert result.to_reachability is not None


@pytest.mark.asyncio
async def test_a_missing_scan_document_reports_no_label(db):
    result = await _dispatch(db)

    assert result.from_reachability is None
    assert result.to_reachability is None


@pytest.mark.asyncio
async def test_a_partial_reachability_document_reports_the_missing_count_as_zero(db):
    await db.scans.insert_one(_scan(_RELEASE_SCAN, {"coverable_count": _COVERABLE}))
    await db.scans.insert_one(_scan(_HEAD_SCAN, {"analyzed_count": _MOST_ANALYSED}))

    result = await _dispatch(db)

    assert result.from_reachability is not None
    assert result.from_reachability.analyzed_count == _UNREPORTED
    assert result.to_reachability is not None
    assert result.to_reachability.coverable_count == _UNREPORTED
