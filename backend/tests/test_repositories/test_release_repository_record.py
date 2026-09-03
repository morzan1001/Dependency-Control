"""Two deploy jobs can race on the upsert key; the loser must still land its values."""

from datetime import datetime, timedelta, timezone

import pymongo
import pytest
import pytest_asyncio
from pymongo.errors import DuplicateKeyError

from app.models.release import Release
from app.repositories.releases import ReleaseRepository
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_NOW_AS_STORED = _NOW.replace(tzinfo=None)  # BSON keeps UTC without the offset
_PROJECT = "p1"
_ENVIRONMENT = "production"
_SCAN = "scan-1"
_VERSION = "v2.1.0"
_EARLIER_VERSION = "v2.0.0"
_UNIQUE_KEY = [
    ("project_id", pymongo.ASCENDING),
    ("environment", pymongo.ASCENDING),
    ("scan_id", pymongo.ASCENDING),
]
_ONE_RECORD = 1
_FIRST_CALL = 1


@pytest_asyncio.fixture
async def db():
    database = FakeDatabase()
    await database.releases.create_index(_UNIQUE_KEY, unique=True)
    return database


def _competitor_row() -> dict:
    return {
        "_id": "written-by-the-other-job",
        "project_id": _PROJECT,
        "environment": _ENVIRONMENT,
        "scan_id": _SCAN,
        "version": _EARLIER_VERSION,
        "released_at": _NOW - timedelta(minutes=1),
    }


def _lose_the_insert_race(db: FakeDatabase) -> None:
    """What the server does to the loser: the competitor's row is already there and the insert raises."""
    original_update_one = db.releases.update_one
    calls = {"count": 0}

    async def racing_update_one(query, update, upsert: bool = False):
        calls["count"] += 1
        if calls["count"] == _FIRST_CALL:
            await db.releases.insert_one(_competitor_row())
            raise DuplicateKeyError("E11000 duplicate key error")
        return await original_update_one(query, update, upsert=upsert)

    db.releases.update_one = racing_update_one


@pytest.mark.asyncio
async def test_a_lost_insert_race_updates_the_row_the_winner_wrote(db):
    """The in-process collection is single-threaded and its upsert filter is the unique key, so a real
    race cannot happen here: the conflict is injected, and what is proven is the handler, not the race."""
    _lose_the_insert_race(db)

    await ReleaseRepository(db).record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, version=_VERSION, scan_id=_SCAN, released_at=_NOW)
    )

    rows = await db.releases.find({}).to_list(None)
    assert len(rows) == _ONE_RECORD
    assert rows[0]["released_at"] == _NOW_AS_STORED
    assert rows[0]["version"] == _VERSION


@pytest.mark.asyncio
async def test_the_upsert_filter_is_the_key_triple(db):
    """The in-process upsert skips its duplicate check once the filter matches, so what a single
    surviving row shows is that the filter selects on the triple — not that uniqueness is enforced."""
    await ReleaseRepository(db).record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, version=_VERSION, scan_id=_SCAN, released_at=_NOW)
    )
    await ReleaseRepository(db).record(
        Release(
            project_id=_PROJECT,
            environment=_ENVIRONMENT,
            version=_VERSION,
            scan_id=_SCAN,
            released_at=_NOW + timedelta(minutes=1),
        )
    )

    rows = await db.releases.find({}).to_list(None)
    assert len(rows) == _ONE_RECORD
