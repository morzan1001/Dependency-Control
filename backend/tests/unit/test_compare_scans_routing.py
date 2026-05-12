"""Routing test for the MCP ``compare_scans`` chat tool.

After the scan-delta extension (see plans/2026-05-11-scan-delta-extension.md
Task 9), ``compare_scans`` must delegate to the unified
``compute_findings_delta`` service and return its envelope, rather than its
own ad-hoc count+sample shape. This test pins that routing contract.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.permissions import PRESET_ADMIN
from app.models.user import User
from app.schemas.scan_delta import DeltaCategory, ScanDeltaResponse, ScanDeltaTotals
from app.services.chat.tools import ChatToolRegistry


@pytest.fixture
def admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(PRESET_ADMIN),
    )


@pytest.mark.asyncio
async def test_compare_scans_routes_through_findings_service(db, admin_user):
    """compare_scans must call compute_findings_delta and return its envelope."""
    db.projects._docs["p1"] = {"_id": "p1", "name": "test-project", "team_id": None}
    await db["scans"].insert_many(
        [
            {"_id": "sa", "project_id": "p1", "created_at": datetime.now(timezone.utc)},
            {"_id": "sb", "project_id": "p1", "created_at": datetime.now(timezone.utc)},
        ]
    )

    fake_response = ScanDeltaResponse(
        from_scan_id="sa",
        to_scan_id="sb",
        project_id="p1",
        category=DeltaCategory.FINDINGS,
        totals=ScanDeltaTotals(added=1, removed=0, unchanged=0),
        page=1,
        page_size=50,
        total_pages=1,
        items=[],
    )

    with patch(
        "app.services.chat.tools.registry.compute_findings_delta",
        new=AsyncMock(return_value=fake_response),
    ) as mock:
        result = await ChatToolRegistry()._dispatch(
            "compare_scans",
            {"project_id": "p1", "scan_id_a": "sa", "scan_id_b": "sb"},
            admin_user,
            db,
        )

    mock.assert_awaited_once()
    call_kwargs = mock.await_args.kwargs
    assert call_kwargs["project_id"] == "p1"
    assert call_kwargs["from_scan"] == "sa"
    assert call_kwargs["to_scan"] == "sb"
    assert result["category"] == "findings"
    assert result["totals"]["added"] == 1
    assert result["from_scan_id"] == "sa"
    assert result["to_scan_id"] == "sb"


@pytest.mark.asyncio
async def test_compare_scans_returns_error_when_project_not_authorized(db, admin_user):
    """Auth check still runs: unknown project_id is rejected before the service is called."""
    with patch(
        "app.services.chat.tools.registry.compute_findings_delta",
        new=AsyncMock(),
    ) as mock:
        result = await ChatToolRegistry()._dispatch(
            "compare_scans",
            {"project_id": "missing", "scan_id_a": "sa", "scan_id_b": "sb"},
            admin_user,
            db,
        )

    assert result == {"error": "Project not found or access denied"}
    mock.assert_not_awaited()
