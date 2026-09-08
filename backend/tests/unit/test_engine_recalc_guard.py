"""_project_has_active_waivers decides whether the post-analysis waiver recalc runs at all."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.analysis.engine import _project_has_active_waivers
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "proj-456"
_OTHER_PROJECT = "proj-other"
_NOW = datetime.now(timezone.utc)
_YEAR = timedelta(days=365)


async def _seeded(*waivers) -> FakeDatabase:
    db = FakeDatabase()
    for index, waiver in enumerate(waivers):
        await db.waivers.insert_one({"_id": f"w{index}", **waiver})
    return db


class TestProjectHasActiveWaivers:
    @pytest.mark.asyncio
    async def test_no_waivers_at_all_skips_the_recalc(self):
        assert await _project_has_active_waivers(_PROJECT, await _seeded()) is False

    @pytest.mark.asyncio
    async def test_a_waiver_scoped_to_this_project_triggers_the_recalc(self):
        db = await _seeded({"project_id": _PROJECT, "expiration_date": None})

        assert await _project_has_active_waivers(_PROJECT, db) is True

    @pytest.mark.asyncio
    async def test_a_global_waiver_triggers_the_recalc_for_every_project(self):
        db = await _seeded({"project_id": None})

        assert await _project_has_active_waivers(_PROJECT, db) is True

    @pytest.mark.asyncio
    async def test_another_projects_waiver_and_an_expired_global_one_leave_it_skipped(self):
        db = await _seeded(
            {"project_id": _OTHER_PROJECT, "expiration_date": None},
            {"project_id": None, "expiration_date": _NOW - _YEAR},
        )

        assert await _project_has_active_waivers(_PROJECT, db) is False

    @pytest.mark.asyncio
    async def test_a_waiver_expiring_in_the_future_still_counts(self):
        db = await _seeded({"project_id": _PROJECT, "expiration_date": _NOW + _YEAR})

        assert await _project_has_active_waivers(_PROJECT, db) is True

    @pytest.mark.asyncio
    async def test_the_check_stops_at_the_first_match(self):
        """limit=1 is the whole point of the helper and no result assertion can observe it."""
        db = SimpleNamespace(waivers=SimpleNamespace(count_documents=AsyncMock(return_value=0)))

        await _project_has_active_waivers(_PROJECT, db)  # type: ignore[arg-type]

        assert db.waivers.count_documents.await_args.kwargs.get("limit") == 1
