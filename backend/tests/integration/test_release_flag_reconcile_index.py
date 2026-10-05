"""The reconcile hints scans_released_list by name, and housekeeping swallows the error a rename would raise."""

import pytest

from app.core.init_db import create_indexes
from app.services.releases import reconcile_release_flags

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]


async def test_the_reconcile_runs_against_the_indexes_startup_creates(db):
    await create_indexes(db)
    await db.scans.insert_one({"_id": "flagged-without-a-row", "project_id": "p1", "is_release": True})

    assert await reconcile_release_flags(db) == (1, 0)
