from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.scan_delta import DeltaCategory, ScanDeltaResponse, ScanDeltaTotals
from app.services.analytics.scan_delta import InvalidDeltaQuery, compute_scan_delta_dispatch

_PROJECT = "p1"
_FROM_SCAN = "a"
_TO_SCAN = "b"
_SAME_SCAN = "same"

_FINDINGS = "findings"
_COMPONENTS = "components"
_CRYPTO = "crypto"

_PAGE = 1
_PAGE_SIZE = 50
_PAGE_BELOW_MINIMUM = 0
_PAGE_SIZE_ABOVE_MAXIMUM = 500

_CRITICAL = ["critical"]
_UPPERCASE_CRITICAL = ["CRITICAL"]
_MISSPELLED_SEVERITY = ["criticla"]
_MISSPELLED_UPPERCASE_SEVERITY = ["CRITICLA"]
_SECRET = ["secret"]
_UNKNOWN_FINDING_TYPE = ["bogus"]
_CHANGED = "changed"
_UNKNOWN_CHANGE = "garbage"


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
        "app.services.analytics.scan_delta.compute_findings_delta",
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
        "app.services.analytics.scan_delta.compute_components_delta",
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
        "app.services.analytics.scan_delta.compute_crypto_delta_envelope",
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
async def test_dispatch_rejects_change_changed_for_non_components(db):
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_FINDINGS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=_CHANGED,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )


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
        "app.services.analytics.scan_delta.compute_findings_delta",
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
    with pytest.raises(InvalidDeltaQuery, match=f"change={_UNKNOWN_CHANGE}"):
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
async def test_dispatch_accepts_change_changed_for_components(db):
    with patch(
        "app.services.analytics.scan_delta.compute_components_delta",
        new=AsyncMock(return_value=_envelope(DeltaCategory.COMPONENTS)),
    ):
        result = await compute_scan_delta_dispatch(
            db=db,
            project_id=_PROJECT,
            category=_COMPONENTS,
            from_scan=_FROM_SCAN,
            to_scan=_TO_SCAN,
            page=_PAGE,
            page_size=_PAGE_SIZE,
            change=_CHANGED,
            severity=None,
            finding_type=None,
            allow_same_scan=False,
        )
        assert result.category == DeltaCategory.COMPONENTS
