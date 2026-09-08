"""Which scans retention is allowed to touch: the age window, and the action a project inherits."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.core.housekeeping import run_housekeeping
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"

_PROJECT_ID = "p1"
_RETENTION_DAYS = 30
_EXPIRED_ID = "expired"
_FRESH_ID = "fresh"
_NOW = datetime.now(timezone.utc)
_EXPIRED_AT = _NOW - timedelta(days=_RETENTION_DAYS * 2)
_FRESH_AT = _NOW - timedelta(days=1)


def _scan_doc(scan_id: str, created_at: datetime) -> dict[str, Any]:
    return {"_id": scan_id, "project_id": _PROJECT_ID, "status": "completed", "created_at": created_at}


async def _seed_scans(db: FakeDatabase) -> None:
    await db.scans.insert_one(_scan_doc(_EXPIRED_ID, _EXPIRED_AT))
    await db.scans.insert_one(_scan_doc(_FRESH_ID, _FRESH_AT))


async def _run(db: FakeDatabase, monkeypatch: pytest.MonkeyPatch, archive_enabled: bool = False) -> AsyncMock:
    archiver = AsyncMock(return_value=0)
    monkeypatch.setattr(f"{MODULE}.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: archive_enabled)
    monkeypatch.setattr(f"{MODULE}._archive_scans_and_delete", archiver)
    await run_housekeeping()
    return archiver


async def _surviving_ids(db: FakeDatabase) -> list[str]:
    return sorted(doc["_id"] for doc in await db.scans.find({}).to_list(None))


@pytest.mark.asyncio
async def test_only_scans_older_than_the_window_are_deleted(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cutoff computed in the wrong direction takes the whole estate with it."""
    db = FakeDatabase()
    await db.system_settings.insert_one(
        {
            "_id": "current",
            "retention_mode": "global",
            "global_retention_days": _RETENTION_DAYS,
            "global_retention_action": "delete",
        }
    )
    await _seed_scans(db)

    await _run(db, monkeypatch)

    assert await _surviving_ids(db) == [_FRESH_ID]


@pytest.mark.asyncio
async def test_a_project_that_names_no_action_is_cleaned_by_deleting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inheriting 'archive' instead would silently keep every expired scan whenever S3 is off."""
    db = FakeDatabase()
    await db.system_settings.insert_one({"_id": "current", "retention_mode": "project"})
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "p", "retention_days": _RETENTION_DAYS})
    await _seed_scans(db)

    archiver = await _run(db, monkeypatch, archive_enabled=True)

    assert await _surviving_ids(db) == [_FRESH_ID]
    archiver.assert_not_awaited()
