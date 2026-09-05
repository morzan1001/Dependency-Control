"""A model that asked for more than a chat tool grants must be told it was given less.

The clamp is silent otherwise: the tool answers with the ceiling's worth of rows and the model
relays them as the whole of what it asked about.
"""

from datetime import datetime, timezone

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import MAX_SUMMARY_ROWS, _clamp_limit, begin_limit_ledger, clamped_limit_note
from tests.helpers.permission_presets import PRESET_ADMIN

_NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
_PROJECT = "checkout-service"
_SCAN = "scan-head"
_DEFAULT = 10
_CEILING = MAX_SUMMARY_ROWS
_ASKED_FOR = _CEILING * 3


@pytest.fixture
def admin_user():
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


@pytest.fixture
def seeded(db):
    db.projects._docs[_PROJECT] = {"_id": _PROJECT, "name": _PROJECT, "team_id": None}
    db.scans._docs[_SCAN] = {
        "_id": _SCAN,
        "project_id": _PROJECT,
        "branch": "main",
        "status": "completed",
        "created_at": _NOW,
        "stats": {},
    }
    return db


class TestLedger:
    def test_a_clamped_request_is_recorded(self):
        begin_limit_ledger()

        assert _clamp_limit(_ASKED_FOR, _DEFAULT, _CEILING) == _CEILING
        assert f"{_ASKED_FOR} to {_CEILING}" in (clamped_limit_note() or "")

    def test_a_request_inside_the_range_is_not_recorded(self):
        begin_limit_ledger()

        assert _clamp_limit(_CEILING - 1, _DEFAULT, _CEILING) == _CEILING - 1
        assert clamped_limit_note() is None

    def test_falling_back_to_the_default_is_not_a_clamp(self):
        """Nothing was asked for, so nothing was refused."""
        begin_limit_ledger()

        assert _clamp_limit(None, _DEFAULT, _CEILING) == _DEFAULT
        assert clamped_limit_note() is None

    def test_a_request_below_the_floor_is_recorded_too(self):
        begin_limit_ledger()

        assert _clamp_limit(0, _DEFAULT, _CEILING) == 1
        assert "0 to 1" in (clamped_limit_note() or "")


@pytest.mark.asyncio
async def test_the_tool_result_says_the_request_was_reduced(seeded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "get_scan_history", {"project_id": _PROJECT, "limit": _ASKED_FOR}, admin_user, seeded
    )

    assert result["_limit_clamped"] is True
    assert f"{_ASKED_FOR} to {_CEILING}" in result["_limit_clamp_note"]


@pytest.mark.asyncio
async def test_a_result_within_the_range_carries_no_note(seeded, admin_user):
    result = await ChatToolRegistry().execute_tool(
        "get_scan_history", {"project_id": _PROJECT, "limit": 5}, admin_user, seeded
    )

    assert "_limit_clamped" not in result
    assert "_limit_clamp_note" not in result


@pytest.mark.asyncio
async def test_one_call_does_not_inherit_the_previous_call_s_clamp(seeded, admin_user):
    registry = ChatToolRegistry()
    await registry.execute_tool("get_scan_history", {"project_id": _PROJECT, "limit": _ASKED_FOR}, admin_user, seeded)

    result = await registry.execute_tool("get_scan_history", {"project_id": _PROJECT, "limit": 5}, admin_user, seeded)

    assert "_limit_clamped" not in result
