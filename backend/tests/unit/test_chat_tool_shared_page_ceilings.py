"""A service reachable through both its REST endpoint and a chat tool is bounded at one number.

Two independently declared ceilings for one read is how a caller ends up believing the smaller
one was the whole of what exists, so each pair is compared against the other here rather than
against the constant both now import.
"""

import inspect
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.compliance_reports import list_reports
from app.api.v1.endpoints.crypto_analytics import get_hotspots
from app.api.v1.endpoints.crypto_assets import list_crypto_assets as list_crypto_assets_endpoint
from app.api.v1.endpoints.pqc_migration import get_pqc_migration_plan
from app.api.v1.endpoints.policy_audit import list_system_audit
from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN

_NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
_PROJECT = "proj-1"
_SCAN = "scan-1"
_BRANCH = "main"
_OVER_ANY_CEILING = 1_000_000


def _endpoint_ceiling(endpoint: Any) -> int:
    """The `le=` FastAPI validates the endpoint's `limit` against."""
    metadata = inspect.signature(endpoint).parameters["limit"].default.metadata
    ceilings = [c.le for c in metadata if isinstance(getattr(c, "le", None), int)]
    assert len(ceilings) == 1
    return int(ceilings[0])


@pytest.fixture
def admin_user():
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


@pytest.fixture
def seeded(db):
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": "P",
        "team_id": None,
        "default_branch": _BRANCH,
        "deleted_branches": [],
        "latest_scan_id": _SCAN,
    }
    db.scans._docs[_SCAN] = {
        "_id": _SCAN,
        "project_id": _PROJECT,
        "branch": _BRANCH,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": _NOW,
    }
    return db


async def _limit_reached_by(tool: str, args: dict[str, Any], target: str, db: Any, user: User) -> int:
    """The `limit` the chat tool hands the service when the caller asks for more than it grants."""
    spy = AsyncMock(return_value={})
    with patch(f"app.services.chat.tools.registry.{target}", new=spy):
        await ChatToolRegistry()._dispatch(tool, {**args, "limit": _OVER_ANY_CEILING}, user, db)
    spy.assert_awaited_once()
    limit = spy.await_args.kwargs["limit"]
    assert isinstance(limit, int)
    return limit


@pytest.mark.asyncio
async def test_crypto_assets(seeded, admin_user):
    reached = await _limit_reached_by(
        "list_crypto_assets", {"project_id": _PROJECT}, "list_crypto_assets", seeded, admin_user
    )
    assert reached == _endpoint_ceiling(list_crypto_assets_endpoint)


@pytest.mark.asyncio
async def test_crypto_hotspots(seeded, admin_user):
    reached = await _limit_reached_by(
        "get_crypto_hotspots", {"project_id": _PROJECT}, "get_crypto_hotspots", seeded, admin_user
    )
    assert reached == _endpoint_ceiling(get_hotspots)


@pytest.mark.asyncio
async def test_pqc_migration_plan(seeded, admin_user):
    reached = await _limit_reached_by(
        "generate_pqc_migration_plan", {"project_id": _PROJECT}, "generate_pqc_migration_plan", seeded, admin_user
    )
    assert reached == _endpoint_ceiling(get_pqc_migration_plan)


@pytest.mark.asyncio
async def test_compliance_reports(seeded, admin_user):
    reached = await _limit_reached_by(
        "list_compliance_reports", {"project_id": _PROJECT}, "list_compliance_reports", seeded, admin_user
    )
    assert reached == _endpoint_ceiling(list_reports)


@pytest.mark.asyncio
async def test_policy_audit_entries(seeded, admin_user):
    reached = await _limit_reached_by(
        "list_policy_audit_entries", {"policy_scope": "system"}, "list_policy_audit_entries", seeded, admin_user
    )
    assert reached == _endpoint_ceiling(list_system_audit)
