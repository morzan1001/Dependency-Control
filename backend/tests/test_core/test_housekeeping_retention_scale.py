"""Retention on an estate whose rescan population no longer fits in a query, and on flags written
outside the model."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.core.constants import ARCHIVE_BATCH_SIZE
from app.core.housekeeping import run_housekeeping
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"

_PROJECT_ID = "p1"
_RETENTION_DAYS = 30
_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_EXPIRED_AT = _NOW - timedelta(days=365)
# More than one batch, and a last batch that is not full.
_CANDIDATE_COUNT = ARCHIVE_BATCH_SIZE * 2 + 3
# In the second batch, so a per-batch lookup has to run more than once to protect it.
_RESCAN_SOURCE_INDEX = ARCHIVE_BATCH_SIZE + 1
_RESCAN_ID = "rescan-of-the-source"
_INT_FLAGGED_RELEASE = "release-flagged-with-one"
_INT_PINNED = "pinned-with-one"
_BOOL_FLAGGED_RELEASE = "release-flagged-with-true"
_UNFLAGGED_RELEASE = "release-with-no-flag"
_ENVIRONMENT = "production"
_INT_TRUE = 1
_NOTHING_LEFT: list[str] = []


def _candidate_id(index: int) -> str:
    return f"expired-{index:04d}"


def _scan_doc(scan_id: str, **overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "status": "completed",
        "created_at": _EXPIRED_AT,
    }
    doc.update(overrides)
    return doc


async def _seed(db: FakeDatabase) -> None:
    await db.system_settings.insert_one(
        {
            "_id": "current",
            "retention_mode": "global",
            "global_retention_days": _RETENTION_DAYS,
            "global_retention_action": "delete",
        }
    )
    for index in range(_CANDIDATE_COUNT):
        await db.scans.insert_one(_scan_doc(_candidate_id(index)))
    await db.scans.insert_one(
        _scan_doc(_RESCAN_ID, created_at=_NOW, is_rescan=True, original_scan_id=_candidate_id(_RESCAN_SOURCE_INDEX))
    )


async def _run(db: FakeDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{MODULE}.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: False)
    await run_housekeeping()


async def _surviving_ids(db: FakeDatabase) -> list[str]:
    return sorted(doc["_id"] for doc in await db.scans.find({"created_at": {"$lt": _NOW}}).to_list(None))


@pytest.mark.asyncio
async def test_the_source_of_a_rescan_survives_retention(monkeypatch: pytest.MonkeyPatch) -> None:
    db = FakeDatabase()
    await _seed(db)

    await _run(db, monkeypatch)

    assert await _surviving_ids(db) == [_candidate_id(_RESCAN_SOURCE_INDEX)]


@pytest.mark.asyncio
async def test_the_retention_cursor_carries_no_list_of_protected_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """The protection set is the whole rescan population; spliced into the cursor it outgrows the
    16 MB document limit and the cursor stops opening at all."""
    db = FakeDatabase()
    await _seed(db)
    queries: list[dict[str, Any]] = []
    original_find = db.scans.find
    db.scans.find = lambda query=None, projection=None, **kwargs: (  # type: ignore[method-assign]
        queries.append(query or {}),
        original_find(query, projection, **kwargs),
    )[1]

    await _run(db, monkeypatch)

    retention_cursors = [query for query in queries if "created_at" in query and "pinned" in query]
    assert retention_cursors, queries
    assert all("_id" not in query for query in retention_cursors), retention_cursors


@pytest.mark.asyncio
async def test_the_rescan_lookup_asks_about_one_batch_at_a_time(monkeypatch: pytest.MonkeyPatch) -> None:
    db = FakeDatabase()
    await _seed(db)
    asked: list[list[str]] = []
    original_find = db.scans.find

    def _record(query=None, projection=None, **kwargs):
        if query and query.get("is_rescan") is True:
            asked.append(query["original_scan_id"]["$in"])
        return original_find(query, projection, **kwargs)

    db.scans.find = _record  # type: ignore[method-assign]

    await _run(db, monkeypatch)

    assert len(asked) > 1, "one lookup means the whole estate was asked about at once"
    assert all(len(batch) <= ARCHIVE_BATCH_SIZE for batch in asked), [len(batch) for batch in asked]


@pytest.mark.asyncio
async def test_a_scan_pinned_with_an_integer_is_not_deleted(monkeypatch: pytest.MonkeyPatch) -> None:
    """BSON int32 is not bool: a pin a migration or a mongosh one-liner wrote as 1 passes
    {"$ne": True}, and retention deletes a scan the operator asked it to keep."""
    db = FakeDatabase()
    await _seed(db)
    await db.scans.insert_one(_scan_doc(_INT_PINNED, pinned=_INT_TRUE))

    await _run(db, monkeypatch)

    assert await _surviving_ids(db) == sorted([_candidate_id(_RESCAN_SOURCE_INDEX), _INT_PINNED])


@pytest.mark.asyncio
async def test_a_release_row_protects_a_scan_whatever_its_flag_spelling(monkeypatch: pytest.MonkeyPatch) -> None:
    """The row decides, so neither spelling of the flag nor its absence changes the answer."""
    db = FakeDatabase()
    await _seed(db)
    for scan_id, flag in ((_INT_FLAGGED_RELEASE, _INT_TRUE), (_BOOL_FLAGGED_RELEASE, True), (_UNFLAGGED_RELEASE, None)):
        overrides = {} if flag is None else {"is_release": flag}
        await db.scans.insert_one(_scan_doc(scan_id, **overrides))
        await db.releases.insert_one(
            {
                "_id": f"row-{scan_id}",
                "project_id": _PROJECT_ID,
                "environment": _ENVIRONMENT,
                "scan_id": scan_id,
                "released_at": _NOW,
            }
        )

    await _run(db, monkeypatch)

    assert await _surviving_ids(db) == sorted(
        [_candidate_id(_RESCAN_SOURCE_INDEX), _INT_FLAGGED_RELEASE, _BOOL_FLAGGED_RELEASE, _UNFLAGGED_RELEASE]
    )


@pytest.mark.asyncio
async def test_a_flag_no_release_row_names_does_not_exempt_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """A flag whose row was never written, or was withdrawn, is not a release: exempting on it is
    an exemption nothing can ever lift."""
    db = FakeDatabase()
    await _seed(db)
    await db.scans.insert_one(_scan_doc(_BOOL_FLAGGED_RELEASE, is_release=True))

    await _run(db, monkeypatch)

    assert await _surviving_ids(db) == [_candidate_id(_RESCAN_SOURCE_INDEX)]
