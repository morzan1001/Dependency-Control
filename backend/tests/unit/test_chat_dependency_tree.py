"""get_dependency_tree answers with a page of short rows, direct dependencies first, that the model can narrow."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "p-1"
_HEAD = "scan-head"
_PARENTS = [f"pkg:npm/parent-{index}@1.0.0" for index in range(8)]
# name -> direct; seeded out of order so only the sort can put them in order.
_DEPENDENCIES = {"zeta": True, "beta-lib": False, "alpha": True, "a-lib": False}
_DIRECT_FIRST = ["alpha", "zeta", "a-lib", "beta-lib"]


def _seeded() -> FakeDatabase:
    db = FakeDatabase()
    db.projects._docs[_PROJECT] = {"_id": _PROJECT, "name": "checkout", "default_branch": "main"}
    db.scans._docs[_HEAD] = {
        "_id": _HEAD,
        "project_id": _PROJECT,
        "branch": "main",
        "status": SCAN_STATUS_COMPLETED,
        "created_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
    }
    for name, direct in _DEPENDENCIES.items():
        db.dependencies._docs[f"dep-{name}"] = {
            "_id": f"dep-{name}",
            "project_id": _PROJECT,
            "scan_id": _HEAD,
            "name": name,
            "version": "1.0.0",
            "purl": f"pkg:npm/{name}@1.0.0",
            "direct": direct,
            "description": "a long package description",
            "hashes": {"sha256": "0" * 64},
            "parent_components": [] if direct else _PARENTS,
        }
    return db


async def _tree(args: dict) -> dict:
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)
    return await ChatToolRegistry().execute_tool(
        "get_dependency_tree", {"project_id": _PROJECT, **args}, admin, _seeded()
    )


@pytest.mark.asyncio
async def test_direct_dependencies_come_first_then_by_name():
    rows = (await _tree({}))["dependencies"]

    assert [row["name"] for row in rows] == _DIRECT_FIRST


@pytest.mark.asyncio
async def test_direct_only_lists_and_counts_the_direct_dependencies():
    result = await _tree({"direct_only": True})

    assert [row["name"] for row in result["dependencies"]] == ["alpha", "zeta"]
    assert result["dependencies_total"] == 2


@pytest.mark.asyncio
async def test_the_limit_cuts_the_ordered_list_and_names_the_whole():
    result = await _tree({"limit": 3})

    assert [row["name"] for row in result["dependencies"]] == _DIRECT_FIRST[:3]
    assert result["dependencies_total"] == len(_DEPENDENCIES)


@pytest.mark.asyncio
async def test_each_row_names_at_most_five_parents_and_counts_them_all():
    rows = {row["name"]: row for row in (await _tree({}))["dependencies"]}

    assert (rows["a-lib"]["parents"], rows["a-lib"]["parent_count"]) == (_PARENTS[:5], len(_PARENTS))
    assert (rows["alpha"]["parents"], rows["alpha"]["parent_count"]) == ([], 0)


@pytest.mark.asyncio
async def test_a_row_carries_what_a_tree_row_shows_and_no_dependency_link():
    row = (await _tree({}))["dependencies"][0]

    assert row == {
        "name": "alpha",
        "version": "1.0.0",
        "purl": "pkg:npm/alpha@1.0.0",
        "direct": True,
        "parents": [],
        "parent_count": 0,
    }
