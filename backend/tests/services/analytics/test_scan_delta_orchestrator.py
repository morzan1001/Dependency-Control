import importlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.scan_delta import (
    CryptoDeltaItem,
    DeltaCategory,
    FindingDeltaItem,
    ScanDeltaResponse,
    ScanDeltaSide,
    ScanDeltaTotals,
)
from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_PROCESSING
from app.services.analytics import cache as cache_module
from app.services.analytics.cache import get_delta_cache
from app.services.analytics.scan_delta import _MAX_PAGE_SIZE, InvalidDeltaQuery, compute_scan_delta_dispatch

_PROJECT = "p1"
_FROM_SCAN = "a"
_TO_SCAN = "b"
_SAME_SCAN = "same"
_OTHER_SCAN = "c"

_FINDINGS = "findings"
_COMPONENTS = "components"
_CRYPTO = "crypto"

_PAGE = 1
_PAGE_SIZE = 50
_PAGE_BELOW_MINIMUM = 0
_PAGE_SIZE_ABOVE_MAXIMUM = 500
_PAGE_SIZE_AT_MAXIMUM = _MAX_PAGE_SIZE

_CRITICAL = ["critical"]
_UPPERCASE_CRITICAL = ["CRITICAL"]
_MISSPELLED_SEVERITY = ["criticla"]
_MISSPELLED_UPPERCASE_SEVERITY = ["CRITICLA"]
_SECRET = ["secret"]
_UNKNOWN_FINDING_TYPE = ["bogus"]
_CHANGED = "changed"
_UNKNOWN_CHANGE = "garbage"

_MAIN_BRANCH = "main"
_FROM_COMMIT = "aaa111"
_TO_COMMIT = "bbb222"
_RELEASED_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)
_BUILT_AT = datetime(2026, 9, 1, tzinfo=timezone.utc)
_REANALYSED_AT = datetime(2026, 9, 2, tzinfo=timezone.utc)


async def _dispatch(db, **overrides) -> ScanDeltaResponse:
    query = {
        "project_id": _PROJECT,
        "category": _FINDINGS,
        "from_scan": _FROM_SCAN,
        "to_scan": _TO_SCAN,
        "page": _PAGE,
        "page_size": _PAGE_SIZE,
        "change": None,
        "severity": None,
        "finding_type": None,
        "allow_same_scan": False,
    }
    return await compute_scan_delta_dispatch(db=db, **(query | overrides))


def _findings_comparison(*changes: str) -> ScanDeltaResponse:
    items = [
        FindingDeltaItem(change=change, finding_id=f"f{n}", finding_type="vulnerability", severity="HIGH", title="")
        for n, change in enumerate(changes)
    ]
    return _envelope(DeltaCategory.FINDINGS).model_copy(update={"items": items})


def _envelope(category: DeltaCategory) -> ScanDeltaResponse:
    """A per-category sentinel the dispatcher must hand back untouched."""
    return ScanDeltaResponse(
        from_scan_id=_FROM_SCAN,
        to_scan_id=_TO_SCAN,
        project_id=_PROJECT,
        category=category,
        totals=ScanDeltaTotals(),
    )


@pytest.mark.asyncio
async def test_dispatch_findings(db):
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_envelope(DeltaCategory.FINDINGS)),
    ) as mock:
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )
        assert result.category == DeltaCategory.FINDINGS
        mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_components(db):
    with patch(
        "app.services.analytics.scan_delta.compare_components",
        new=AsyncMock(return_value=_envelope(DeltaCategory.COMPONENTS)),
    ) as mock:
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_COMPONENTS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )
        assert result.category == DeltaCategory.COMPONENTS
        mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_crypto(db):
    with patch(
        "app.services.analytics.scan_delta.compare_crypto",
        new=AsyncMock(return_value=_envelope(DeltaCategory.CRYPTO)),
    ) as mock:
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_CRYPTO,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )
        assert result.category == DeltaCategory.CRYPTO
        mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_rejects_severity_for_non_findings(db):
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_COMPONENTS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=_CRITICAL,
            finding_type=None,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_finding_type_for_non_findings(db):
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_CRYPTO,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=_SECRET,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_crypto_answers_the_shared_change_vocabulary(db):
    """Crypto pairs no changed items, so asking for them is an empty page rather than an error."""
    added = CryptoDeltaItem(change="added", name="MD5")
    with patch(
        "app.services.analytics.scan_delta.compare_crypto",
        new=AsyncMock(return_value=_envelope(DeltaCategory.CRYPTO).model_copy(update={"items": [added]})),
    ):
        result = await _dispatch(db, category=_CRYPTO, change=_CHANGED)

    assert result.items == []


@pytest.mark.asyncio
async def test_dispatch_rejects_same_scan_ids(db):
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_SAME_SCAN,
            to_scan=_SAME_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_severity(db):
    with pytest.raises(InvalidDeltaQuery, match="unknown severity"):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=_MISSPELLED_SEVERITY,
            finding_type=None,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_severity_preserves_user_casing(db):
    """Error echoes the user-typed value, not the lowercased canonical form, so typos round-trip readably."""
    with pytest.raises(InvalidDeltaQuery, match=_MISSPELLED_UPPERCASE_SEVERITY[0]):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=_MISSPELLED_UPPERCASE_SEVERITY,
            finding_type=None,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_accepts_uppercase_severity(db):
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_envelope(DeltaCategory.FINDINGS)),
    ):
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=_UPPERCASE_CRITICAL,
            finding_type=None,
            allow_same_scan=False,
        )
        assert result.category == DeltaCategory.FINDINGS


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_finding_type(db):
    with pytest.raises(InvalidDeltaQuery, match="unknown finding_type"):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=_UNKNOWN_FINDING_TYPE,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_change_for_findings(db):
    with pytest.raises(InvalidDeltaQuery, match=f"unknown change values: {_UNKNOWN_CHANGE}"):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=_UNKNOWN_CHANGE,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_page_below_one(db):
    with pytest.raises(InvalidDeltaQuery, match="page must be"):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE_BELOW_MINIMUM,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_page_size_above_max(db):
    with pytest.raises(InvalidDeltaQuery, match="page_size must be"):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE_ABOVE_MAXIMUM,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )


@pytest.mark.asyncio
async def test_dispatch_accepts_the_maximum_page_size(db):
    """The advertised maximum is inclusive: the largest page a caller may ask for is answered."""
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_envelope(DeltaCategory.FINDINGS)),
    ) as mock:
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE_AT_MAXIMUM,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )
        assert result.category == DeltaCategory.FINDINGS
        assert result.page_size == _PAGE_SIZE_AT_MAXIMUM
        mock.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("category", "service"),
    [(DeltaCategory.COMPONENTS, "compare_components"), (DeltaCategory.FINDINGS, "compare_findings")],
)
async def test_dispatch_accepts_change_changed_for_components_and_findings(db, category, service):
    with patch(
        f"app.services.analytics.scan_delta.{service}",
        new=AsyncMock(return_value=_envelope(category)),
    ):
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=category.value,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=_CHANGED,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )
        assert result.category == category


@pytest.mark.asyncio
async def test_the_envelope_names_the_build_each_side_resolved_to(db):
    """A symbolic side resolves server-side, so the payload has to carry what it landed on."""
    await db.scans.insert_one(
        {"_id": _FROM_SCAN, "branch": _MAIN_BRANCH, "commit_hash": _FROM_COMMIT, "created_at": _RELEASED_AT}
    )
    await db.scans.insert_one(
        {"_id": _TO_SCAN, "branch": _MAIN_BRANCH, "commit_hash": _TO_COMMIT, "created_at": _BUILT_AT}
    )

    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_envelope(DeltaCategory.FINDINGS)),
    ):
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )

    assert result.from_side == ScanDeltaSide(
        scan_id=_FROM_SCAN, branch=_MAIN_BRANCH, commit_hash=_FROM_COMMIT, created_at=_RELEASED_AT
    )
    assert result.to_side == ScanDeltaSide(
        scan_id=_TO_SCAN, branch=_MAIN_BRANCH, commit_hash=_TO_COMMIT, created_at=_BUILT_AT
    )


@pytest.mark.asyncio
async def test_a_side_whose_scan_is_gone_still_names_its_id(db):
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_envelope(DeltaCategory.FINDINGS)),
    ):
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=None,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )

    assert result.to_side == ScanDeltaSide(scan_id=_TO_SCAN)


async def _seed_finished_sides(db, **fields) -> None:
    await db.scans.insert_many(
        [
            {"_id": scan_id, "status": SCAN_STATUS_COMPLETED, "completed_at": _BUILT_AT, "waiver_fingerprint": "w1"}
            | fields
            for scan_id in (_FROM_SCAN, _TO_SCAN)
        ]
    )


@pytest.mark.asyncio
async def test_pages_and_change_filters_slice_one_comparison(db):
    await _seed_finished_sides(db)
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_findings_comparison("added", "added", "changed", "removed")),
    ) as mock:
        second_page = await _dispatch(db, page=2, page_size=1)
        added = await _dispatch(db, change="added")
        changed = await _dispatch(db, change=_CHANGED)

    mock.assert_awaited_once()
    assert (second_page.page, second_page.total_pages, [i.finding_id for i in second_page.items]) == (2, 4, ["f1"])
    assert [i.finding_id for i in added.items] == ["f0", "f1"]
    assert [i.finding_id for i in changed.items] == ["f2"]


@pytest.mark.asyncio
async def test_the_comparison_is_keyed_on_the_filter_set_not_its_spelling(db):
    await _seed_finished_sides(db)
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_findings_comparison("added")),
    ) as mock:
        await _dispatch(db, severity=["critical", "high"])
        await _dispatch(db, severity=["HIGH", "critical"])
        assert mock.await_count == 1
        await _dispatch(db, severity=["critical", "high"], finding_type=_SECRET)
        assert mock.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rewrite",
    [
        pytest.param({"waiver_fingerprint": "w2"}, id="waiver re-stamp"),
        pytest.param({"completed_at": _REANALYSED_AT}, id="re-analysis"),
    ],
)
async def test_a_side_whose_rows_were_rewritten_is_compared_again(db, rewrite):
    """The re-stamp runs after the waiver request returns and writes the fingerprint last, on whichever pod runs it."""
    await _seed_finished_sides(db)
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_findings_comparison("added")),
    ) as mock:
        await _dispatch(db)
        await db.scans.update_one({"_id": _TO_SCAN}, {"$set": rewrite})
        await _dispatch(db)

    assert mock.await_count == 2


@pytest.mark.asyncio
async def test_a_side_still_being_analysed_is_never_cached(db):
    """Re-analysis deletes the scan's findings before inserting new ones, so a comparison read meanwhile is partial."""
    await _seed_finished_sides(db, status=SCAN_STATUS_PROCESSING)
    with patch(
        "app.services.analytics.scan_delta.compare_findings",
        new=AsyncMock(return_value=_findings_comparison("added")),
    ) as mock:
        await _dispatch(db)
        await _dispatch(db)

    assert mock.await_count == 2


@pytest.mark.asyncio
async def test_cached_comparisons_are_bounded_by_their_summed_items(db, monkeypatch):
    monkeypatch.setattr(cache_module, "_DELTA_ROW_BUDGET", 4)
    get_delta_cache.cache_clear()
    await _seed_finished_sides(db)
    await db.scans.insert_one({"_id": _OTHER_SCAN, "status": SCAN_STATUS_COMPLETED})
    try:
        with patch(
            "app.services.analytics.scan_delta.compare_findings",
            new=AsyncMock(side_effect=[_findings_comparison("added", "added"), _findings_comparison("removed")] * 2),
        ) as mock:
            await _dispatch(db)
            await _dispatch(db, to_scan=_OTHER_SCAN)
            await _dispatch(db)
    finally:
        get_delta_cache.cache_clear()

    assert mock.await_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("category", "module", "reads"),
    [
        (_FINDINGS, "findings_delta", 2),
        (_COMPONENTS, "components_delta", 1),
        (_CRYPTO, "crypto_delta", 1),
    ],
)
async def test_a_pair_resolved_onto_one_scan_reads_it_once(db, category, module, reads):
    """Live plus waiver-touched is one findings side."""
    await db.scans.insert_one({"_id": _SAME_SCAN, "status": SCAN_STATUS_COMPLETED, "branch": _MAIN_BRANCH})
    real = importlib.import_module(f"app.services.analytics.{module}").find_window
    with patch(f"app.services.analytics.{module}.find_window", new=AsyncMock(side_effect=real)) as spy:
        result = await _dispatch(db, category=category, from_scan=_SAME_SCAN, to_scan=_SAME_SCAN, allow_same_scan=True)

    assert spy.await_count == reads
    assert result.from_side == result.to_side == ScanDeltaSide(scan_id=_SAME_SCAN, branch=_MAIN_BRANCH)
