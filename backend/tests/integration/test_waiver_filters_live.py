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
