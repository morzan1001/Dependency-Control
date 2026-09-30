"""The summary, the team overview and the hotspots name the same riskiest projects, from their head builds."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_TEAM = "t-1"
# project id -> head build (critical, high); the project document's cached stats say otherwise.
_HEAD_COUNTS = {"p-a": (1, 0), "p-b": (1, 4), "p-c": (0, 9), "p-d": (1, 4)}
_WORST_FIRST = ["p-b", "p-d", "p-a", "p-c"]


def _seeded() -> FakeDatabase:
    db = FakeDatabase()
    db.teams._docs[_TEAM] = {"_id": _TEAM, "name": "payments", "members": []}
    for pid, (critical, high) in _HEAD_COUNTS.items():
        db.projects._docs[pid] = {
            "_id": pid,
            "name": f"name-{pid}",
            "team_ids": [_TEAM],
            "default_branch": "main",
            "latest_scan_id": f"scan-{pid}",
            "stats": {"critical": 50 - critical, "high": 0},
        }
        db.scans._docs[f"scan-{pid}"] = {
            "_id": f"scan-{pid}",
            "project_id": pid,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
            "stats": {"critical": critical, "high": high, "medium": 0, "low": 0},
        }
    return db


async def _call(tool: str, args: dict) -> dict:
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)
    return await ChatToolRegistry().execute_tool(tool, args, admin, _seeded())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args", "key"),
    [
        ("get_analytics_summary", {}, "top_risky_projects"),
        ("get_team_risk_overview", {"team_id": _TEAM}, "top_risky_projects"),
        ("get_hotspots", {"limit": 3}, "hotspots"),
    ],
    ids=["summary", "team-overview", "hotspots"],
)
async def test_ties_on_critical_break_on_high_then_on_the_project_id(tool, args, key):
    rows = (await _call(tool, args))[key]

    assert [row["project_id"] for row in rows] == _WORST_FIRST[:3]


@pytest.mark.asyncio
async def test_the_team_overview_sums_the_head_builds():
    result = await _call("get_team_risk_overview", {"team_id": _TEAM})

    assert result["severity_totals"] == {"critical": 3, "high": 17, "medium": 0, "low": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args"),
    [("list_projects", {}), ("get_team_projects", {"team_id": _TEAM})],
    ids=["list-projects", "team-projects"],
)
async def test_project_rows_carry_their_head_builds_counts(tool, args):
    rows = (await _call(tool, args))["projects"]

    assert {row["id"]: (row["stats"]["critical"], row["stats"]["high"]) for row in rows} == _HEAD_COUNTS
