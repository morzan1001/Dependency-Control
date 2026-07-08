"""Routing test: the MCP get_scan_delta tool must delegate to compute_crypto_delta_envelope and return its envelope."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.user import User
from app.schemas.scan_delta import DeltaCategory, ScanDeltaResponse, ScanDeltaTotals
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN


@pytest.fixture
def admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(PRESET_ADMIN),
    )


@pytest.mark.asyncio
async def test_get_scan_delta_routes_through_crypto_envelope(db, admin_user):
    db.projects._docs["p1"] = {"_id": "p1", "name": "test-project", "team_id": None}
    await db["scans"].insert_many(
        [
            {"_id": "s1", "project_id": "p1"},
            {"_id": "s2", "project_id": "p1"},
        ]
    )

    fake_response = ScanDeltaResponse(
        from_scan_id="s1",
        to_scan_id="s2",
        project_id="p1",
        category=DeltaCategory.CRYPTO,
        totals=ScanDeltaTotals(added=2, removed=1, unchanged=3),
        page=1,
        page_size=50,
        total_pages=1,
        items=[],
    )

    with patch(
        "app.services.chat.tools.registry.compute_crypto_delta_envelope",
        new=AsyncMock(return_value=fake_response),
    ) as mock:
        result = await ChatToolRegistry()._dispatch(
            "get_scan_delta",
            {"project_id": "p1", "from_scan_id": "s1", "to_scan_id": "s2"},
            admin_user,
            db,
        )

    mock.assert_awaited_once()
    call_kwargs = mock.await_args.kwargs
    assert call_kwargs["project_id"] == "p1"
    assert call_kwargs["from_scan"] == "s1"
    assert call_kwargs["to_scan"] == "s2"
    assert call_kwargs["page"] == 1
    assert call_kwargs["page_size"] == 50
    assert call_kwargs["change"] is None
    assert result["category"] == "crypto"
    assert result["totals"]["added"] == 2
    assert result["totals"]["removed"] == 1
    assert result["totals"]["unchanged"] == 3
    assert result["from_scan_id"] == "s1"
    assert result["to_scan_id"] == "s2"


@pytest.mark.asyncio
async def test_get_scan_delta_returns_error_when_project_not_authorized(db, admin_user):
    with patch(
        "app.services.chat.tools.registry.compute_crypto_delta_envelope",
        new=AsyncMock(),
    ) as mock:
        result = await ChatToolRegistry()._dispatch(
            "get_scan_delta",
            {"project_id": "missing", "from_scan_id": "s1", "to_scan_id": "s2"},
            admin_user,
            db,
        )

    assert result == {"error": "Project not found or access denied"}
    mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_scan_delta_rejects_scan_from_another_project(db, admin_user):
    db.projects._docs["p1"] = {"_id": "p1", "name": "test-project", "team_id": None}
    await db["scans"].insert_many(
        [
            {"_id": "s1", "project_id": "p1"},
            {"_id": "foreign", "project_id": "p_other"},
        ]
    )

    with patch(
        "app.services.chat.tools.registry.compute_crypto_delta_envelope",
        new=AsyncMock(),
    ) as mock:
        result = await ChatToolRegistry()._dispatch(
            "get_scan_delta",
            {"project_id": "p1", "from_scan_id": "s1", "to_scan_id": "foreign"},
            admin_user,
            db,
        )

    assert result == {"error": "Scan not found in this project"}
    mock.assert_not_awaited()
