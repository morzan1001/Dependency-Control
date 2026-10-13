"""The waiver query and the active-waiver filter on a real server: a rule_id reaching into the
merged SAST entries' array and a null equality matching a missing field are server semantics."""

from datetime import datetime, timedelta, timezone

import pytest

from app.repositories.waivers import WaiverRepository
from app.services.waivers.matching import waiver_query
from tests.test_services.test_waivers.test_criteria import _CASES, _FINDINGS

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]


@pytest.mark.parametrize(("waiver", "expected"), _CASES.values(), ids=_CASES.keys())
async def test_the_waiver_query_selects_what_the_in_memory_check_selects(db, waiver, expected):
    await db.findings.insert_many([dict(f) for f in _FINDINGS])

    assert {doc["_id"] async for doc in db.findings.find(waiver_query(waiver))} == expected


async def test_a_waiver_without_an_expiration_date_is_active_and_an_expired_one_is_not(db):
    await db.waivers.insert_many(
        [
            {"_id": "no-expiry", "project_id": "p", "reason": "r", "created_by": "u"},
            {
                "_id": "expired",
                "project_id": "p",
                "reason": "r",
                "created_by": "u",
                "expiration_date": datetime.now(timezone.utc) - timedelta(days=1),
            },
        ]
    )
    repo = WaiverRepository(db)

    assert [w.id for w in await repo.find_active_for_project("p")] == ["no-expiry"]
    assert await repo.find_active_for_project("other") == []


@pytest.mark.parametrize(
    ("sort_order", "skip", "expected"),
    [
        (1, 0, ["by-adam", "legacy", "by-zoe", "by-zoe-2"]),
        (-1, 0, ["by-zoe", "by-zoe-2", "legacy", "by-adam"]),
        (1, 1, ["legacy", "by-zoe"]),
    ],
    ids=["ascending", "descending", "second-page"],
)
async def test_a_page_by_creator_follows_the_current_usernames(db, sort_order, skip, expected):
    await db.users.insert_many([{"_id": "u-1", "username": "zoe"}, {"_id": "u-2", "username": "adam"}])
    creators = {"by-zoe": "u-1", "by-zoe-2": "u-1", "by-adam": "u-2", "legacy": "mia", "other-project": "u-2"}
    await db.waivers.insert_many(
        [
            {"_id": wid, "project_id": "other" if wid == "other-project" else "p", "reason": "r", "created_by": by}
            for wid, by in creators.items()
        ]
    )

    page = await WaiverRepository(db).find_many_by_creator_name(
        {"project_id": "p"}, skip, 2 if skip else 10, sort_order
    )

    assert [(w.id, w.created_by) for w in page] == [(wid, creators[wid]) for wid in expected]
