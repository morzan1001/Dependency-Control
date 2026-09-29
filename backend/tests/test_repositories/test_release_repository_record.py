"""Two deploy jobs can race on the upsert key; the loser must still land its values."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from pymongo.errors import DuplicateKeyError

from app.models.release import Release
from app.repositories.releases import ReleaseRepository
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_PROJECT = "p1"
_ENVIRONMENT = "production"
_SCAN = "scan-1"
_VERSION = "v2.1.0"
_EARLIER_VERSION = "v2.0.0"
_ONE_RECORD = 1
_FIRST_CALL = 1


@pytest_asyncio.fixture
async def db():
    return FakeDatabase()


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
    original = db.releases.find_one_and_update
    calls = {"count": 0}

    async def racing_find_one_and_update(query, update, **kwargs):
        calls["count"] += 1
        if calls["count"] == _FIRST_CALL:
            await db.releases.insert_one(_competitor_row())
            raise DuplicateKeyError("E11000 duplicate key error")
        return await original(query, update, **kwargs)

    db.releases.find_one_and_update = racing_find_one_and_update


@pytest.mark.asyncio
async def test_a_lost_insert_race_updates_the_row_the_winner_wrote(db):
    """The in-process collection is single-threaded and its upsert filter is the unique key, so a real
    race cannot happen here: the conflict is injected, and what is proven is the handler, not the race."""
    _lose_the_insert_race(db)

    stored = await ReleaseRepository(db).record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, version=_VERSION, scan_id=_SCAN, released_at=_NOW)
    )

    rows = await db.releases.find({}).to_list(None)
    assert len(rows) == _ONE_RECORD
    assert rows[0]["released_at"] == _NOW
    assert rows[0]["version"] == _VERSION
    assert stored is not None
    assert stored["_id"] == "written-by-the-other-job"


@pytest.mark.asyncio
async def test_a_second_row_for_one_triple_is_refused(db):
    """The constraint the retry handler exists for: recording is only idempotent because the server
    refuses the second insert."""
    await ReleaseRepository(db).record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, version=_VERSION, scan_id=_SCAN, released_at=_NOW)
    )

    with pytest.raises(DuplicateKeyError):
        await db.releases.insert_one(_competitor_row())


@pytest.mark.asyncio
async def test_the_upsert_filter_is_the_key_triple(db):
    """A filter selecting on anything but the triple would insert, and the unique key would refuse
    the insert, so one surviving row is the filter and the constraint agreeing."""
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


@pytest.mark.asyncio
async def test_record_answers_with_the_stored_row_so_an_unversioned_re_mark_keeps_the_version(db):
    repo = ReleaseRepository(db)
    await repo.record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, version=_VERSION, scan_id=_SCAN, released_at=_NOW)
    )

    stored = await repo.record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, scan_id=_SCAN, released_at=_NOW + timedelta(minutes=1))
    )

    assert stored is not None
    assert (stored["version"], stored["released_at"]) == (_VERSION, _NOW + timedelta(minutes=1))


@pytest.mark.asyncio
async def test_withdraw_names_the_environments_the_scan_still_runs_in(db):
    repo = ReleaseRepository(db)
    for environment in (_ENVIRONMENT, "staging"):
        await repo.record(Release(project_id=_PROJECT, environment=environment, scan_id=_SCAN, released_at=_NOW))

    assert await repo.withdraw(_PROJECT, _ENVIRONMENT, _SCAN) == ["staging"]
    assert await repo.withdraw(_PROJECT, _ENVIRONMENT, _SCAN) is None
    assert await repo.withdraw(_PROJECT, "staging", _SCAN) == []


@pytest.mark.asyncio
async def test_the_latest_release_of_an_environment_is_the_newest_mark(db):
    repo = ReleaseRepository(db)
    await repo.record(Release(project_id=_PROJECT, environment=_ENVIRONMENT, scan_id="older", released_at=_NOW))
    await repo.record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, scan_id="newer", released_at=_NOW + timedelta(hours=1))
    )
    await repo.record(
        Release(project_id=_PROJECT, environment="staging", scan_id="elsewhere", released_at=_NOW + timedelta(days=1))
    )

    latest = await repo.latest_for_environment(_PROJECT, _ENVIRONMENT)

    assert latest is not None
    assert latest["scan_id"] == "newer"
    assert await repo.latest_for_environment(_PROJECT, "absent") is None


@pytest.mark.asyncio
async def test_an_empty_version_is_not_stored_as_the_release_name(db):
    """CI sends an unset tag as "", which must not overwrite or name the release."""
    repo = ReleaseRepository(db)
    await repo.record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, version=_VERSION, scan_id=_SCAN, released_at=_NOW)
    )

    stored = await repo.record(
        Release(project_id=_PROJECT, environment=_ENVIRONMENT, version="", scan_id=_SCAN, released_at=_NOW)
    )
    fresh = await repo.record(
        Release(project_id=_PROJECT, environment="staging", version="", scan_id=_SCAN, released_at=_NOW)
    )

    assert stored is not None
    assert stored["version"] == _VERSION
    assert fresh is not None
    assert "version" not in fresh


@pytest.mark.asyncio
async def test_a_scans_releases_on_one_timestamp_come_back_in_the_list_order(db):
    for release_id in ("rel-b", "rel-a"):
        await db.releases.insert_one(
            {
                "_id": release_id,
                "project_id": _PROJECT,
                "environment": release_id,
                "scan_id": _SCAN,
                "released_at": _NOW,
            }
        )

    grouped = await ReleaseRepository(db).group_by_scan([_SCAN])

    assert [release.id for release in grouped[_SCAN]] == ["rel-a", "rel-b"]


@pytest.mark.asyncio
async def test_released_among_names_the_scans_a_release_row_holds(db):
    repo = ReleaseRepository(db)
    await repo.record(Release(project_id=_PROJECT, environment=_ENVIRONMENT, scan_id="marked", released_at=_NOW))

    assert await repo.released_among(["marked", "unmarked"]) == {"marked"}
