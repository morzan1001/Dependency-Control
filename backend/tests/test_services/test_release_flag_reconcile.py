"""db.releases is the record; Scan.is_release only denormalises it, and both writers can lose the
second of their two writes in either direction."""

from datetime import datetime, timezone

import pytest

from app.services.releases import reconcile_release_flags
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_PROJECT_ID = "p1"
_PRODUCTION = "production"
_STAGING = "staging"
_STALE = "scan-flagged-with-no-row"
_RELEASED = "scan-with-a-row"
_UNTOUCHED = "scan-nobody-released"
_INT_TRUE = 1
_SMALL_BATCH = 2
_OVER_ONE_BATCH = _SMALL_BATCH * 2 + 1


async def _scan(db: FakeDatabase, scan_id: str, **overrides: object) -> None:
    await db.scans.insert_one({"_id": scan_id, "project_id": _PROJECT_ID, "status": "completed", **overrides})


async def _row(db: FakeDatabase, scan_id: str, environment: str = _PRODUCTION) -> None:
    await db.releases.insert_one(
        {
            "_id": f"row-{scan_id}-{environment}",
            "project_id": _PROJECT_ID,
            "environment": environment,
            "scan_id": scan_id,
            "released_at": _NOW,
        }
    )


async def _flag(db: FakeDatabase, scan_id: str) -> object:
    doc = await db.scans.find_one({"_id": scan_id}, {"is_release": 1})
    return doc.get("is_release")


@pytest.mark.asyncio
async def test_a_flag_no_release_row_names_is_cleared() -> None:
    db = FakeDatabase()
    await _scan(db, _STALE, is_release=True)

    assert await reconcile_release_flags(db) == (1, 0)
    assert await _flag(db, _STALE) is False


@pytest.mark.asyncio
async def test_a_release_row_whose_scan_lost_the_flag_is_restored() -> None:
    db = FakeDatabase()
    await _scan(db, _RELEASED)
    await _row(db, _RELEASED)

    assert await reconcile_release_flags(db) == (0, 1)
    assert await _flag(db, _RELEASED) is True


@pytest.mark.asyncio
async def test_a_scan_still_released_to_another_environment_keeps_its_flag() -> None:
    """The flag says 'this scan has a release record', not 'this scan is released to production'."""
    db = FakeDatabase()
    await _scan(db, _RELEASED, is_release=True)
    await _row(db, _RELEASED, _STAGING)

    assert await reconcile_release_flags(db) == (0, 0)
    assert await _flag(db, _RELEASED) is True


@pytest.mark.asyncio
async def test_a_scan_nobody_released_is_left_alone() -> None:
    db = FakeDatabase()
    await _scan(db, _UNTOUCHED)

    assert await reconcile_release_flags(db) == (0, 0)
    assert await _flag(db, _UNTOUCHED) is None


@pytest.mark.asyncio
async def test_a_second_pass_over_the_same_estate_writes_nothing() -> None:
    """A pass that keeps reporting work is a pass whose write does not settle the divergence."""
    db = FakeDatabase()
    await _scan(db, _STALE, is_release=True)
    await _scan(db, _RELEASED)
    await _row(db, _RELEASED)

    assert await reconcile_release_flags(db) == (1, 1)
    assert await reconcile_release_flags(db) == (0, 0)


@pytest.mark.asyncio
async def test_a_ghost_release_row_does_not_stop_the_pass() -> None:
    """A row whose scan is gone is the state the ghost-row audit is about; it must not raise."""
    db = FakeDatabase()
    await _scan(db, _STALE, is_release=True)
    await _row(db, "scan-that-no-longer-exists")

    assert await reconcile_release_flags(db) == (1, 0)


@pytest.mark.asyncio
async def test_neither_direction_asks_about_the_whole_estate_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every flagged scan in one $in, or every release row in one, outgrows the 16 MB limit."""
    monkeypatch.setattr("app.services.releases.RELEASE_FLAG_RECONCILE_BATCH_SIZE", _SMALL_BATCH)
    db = FakeDatabase()
    for index in range(_OVER_ONE_BATCH):
        await _scan(db, f"{_STALE}-{index}", is_release=True)
        await _scan(db, f"{_RELEASED}-{index}")
        await _row(db, f"{_RELEASED}-{index}")

    asked: list[int] = []
    original_distinct = db.releases.distinct
    original_update = db.scans.update_many

    async def _record_distinct(field, filter=None):
        asked.append(len(filter["scan_id"]["$in"]))
        return await original_distinct(field, filter)

    async def _record_update(query, update, **kwargs):
        asked.append(len(query["_id"]["$in"]))
        return await original_update(query, update, **kwargs)

    db.releases.distinct = _record_distinct  # type: ignore[method-assign]
    db.scans.update_many = _record_update  # type: ignore[method-assign]

    assert await reconcile_release_flags(db) == (_OVER_ONE_BATCH, _OVER_ONE_BATCH)
    assert asked, "the reconcile issued no batched query at all"
    assert max(asked) <= _SMALL_BATCH, asked


@pytest.mark.asyncio
async def test_an_integer_flag_is_repaired_to_the_boolean_the_partial_index_is_keyed_on() -> None:
    """BSON int32 is not bool, so a flag written as 1 is outside the scans_released_list index."""
    db = FakeDatabase()
    await _scan(db, _RELEASED, is_release=_INT_TRUE)
    await _row(db, _RELEASED)

    assert await reconcile_release_flags(db) == (0, 1)
    assert await _flag(db, _RELEASED) is True
