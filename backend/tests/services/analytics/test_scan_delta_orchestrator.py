import pytest
from unittest.mock import AsyncMock, patch
from app.services.analytics.scan_delta import compute_scan_delta_dispatch, InvalidDeltaQuery


@pytest.mark.asyncio
async def test_dispatch_findings():
    with patch(
        "app.services.analytics.scan_delta.compute_findings_delta",
        new=AsyncMock(return_value="findings-result"),
    ) as mock:
        result = await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change=None, severity=None, finding_type=None,
        )
        assert result == "findings-result"
        mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_components():
    with patch(
        "app.services.analytics.scan_delta.compute_components_delta",
        new=AsyncMock(return_value="components-result"),
    ) as mock:
        result = await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="components",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change=None, severity=None, finding_type=None,
        )
        assert result == "components-result"
        mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_crypto():
    with patch(
        "app.services.analytics.scan_delta.compute_crypto_delta_envelope",
        new=AsyncMock(return_value="crypto-result"),
    ) as mock:
        result = await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="crypto",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change=None, severity=None, finding_type=None,
        )
        assert result == "crypto-result"
        mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_rejects_severity_for_non_findings():
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="components",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change=None, severity=["critical"], finding_type=None,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_finding_type_for_non_findings():
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="crypto",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change=None, severity=None, finding_type=["secret"],
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_change_changed_for_non_components():
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change="changed", severity=None, finding_type=None,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_same_scan_ids():
    with pytest.raises(InvalidDeltaQuery):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="same", to_scan="same", page=1, page_size=50,
            change=None, severity=None, finding_type=None,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_severity():
    with pytest.raises(InvalidDeltaQuery, match="unknown severity"):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change=None, severity=["criticla"], finding_type=None,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_finding_type():
    with pytest.raises(InvalidDeltaQuery, match="unknown finding_type"):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change=None, severity=None, finding_type=["bogus"],
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_change_for_findings():
    with pytest.raises(InvalidDeltaQuery, match="change=garbage"):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change="garbage", severity=None, finding_type=None,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_page_below_one():
    with pytest.raises(InvalidDeltaQuery, match="page must be"):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="a", to_scan="b", page=0, page_size=50,
            change=None, severity=None, finding_type=None,
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_page_size_above_max():
    with pytest.raises(InvalidDeltaQuery, match="page_size must be"):
        await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="findings",
            from_scan="a", to_scan="b", page=1, page_size=500,
            change=None, severity=None, finding_type=None,
        )


@pytest.mark.asyncio
async def test_dispatch_accepts_change_changed_for_components():
    with patch(
        "app.services.analytics.scan_delta.compute_components_delta",
        new=AsyncMock(return_value="components-result"),
    ):
        result = await compute_scan_delta_dispatch(
            db=None, project_id="p1", category="components",
            from_scan="a", to_scan="b", page=1, page_size=50,
            change="changed", severity=None, finding_type=None,
        )
        assert result == "components-result"
