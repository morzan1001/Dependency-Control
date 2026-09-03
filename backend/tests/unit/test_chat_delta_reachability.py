"""The chat and MCP delta tools return the per-category envelope directly. An unlabelled envelope
would tell the model that a reachability-enriched scan reports no reachability at all."""

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN

_PROJECT = "p1"
_ENRICHED_SCAN = "sa"
_RESCANNED_SCAN = "sb"

_COVERABLE = 9
_ANALYSED = 9


@pytest.fixture
def admin_user():
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(PRESET_ADMIN),
    )


async def _seed_one_enriched_side(db) -> None:
    db.projects._docs[_PROJECT] = {"_id": _PROJECT, "name": "test-project", "team_id": None}
    await db["scans"].insert_many(
        [
            {
                "_id": _ENRICHED_SCAN,
                "project_id": _PROJECT,
                "stats": {"reachability": {"coverable_count": _COVERABLE, "analyzed_count": _ANALYSED}},
            },
            {"_id": _RESCANNED_SCAN, "project_id": _PROJECT},
        ]
    )


@pytest.mark.asyncio
async def test_compare_scans_payload_labels_both_sides(db, admin_user):
    await _seed_one_enriched_side(db)

    result = await ChatToolRegistry()._dispatch(
        "compare_scans",
        {"project_id": _PROJECT, "scan_id_a": _ENRICHED_SCAN, "scan_id_b": _RESCANNED_SCAN},
        admin_user,
        db,
    )

    assert result["from_reachability"] == {"coverable_count": _COVERABLE, "analyzed_count": _ANALYSED}
    assert result["to_reachability"] is None


@pytest.mark.asyncio
async def test_get_scan_delta_payload_labels_both_sides(db, admin_user):
    await _seed_one_enriched_side(db)

    result = await ChatToolRegistry()._dispatch(
        "get_scan_delta",
        {"project_id": _PROJECT, "from_scan_id": _ENRICHED_SCAN, "to_scan_id": _RESCANNED_SCAN},
        admin_user,
        db,
    )

    assert result["from_reachability"] == {"coverable_count": _COVERABLE, "analyzed_count": _ANALYSED}
    assert result["to_reachability"] is None
