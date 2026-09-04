"""A release must survive retention: the delete path drops nine collections plus GridFS, and the
archive path removes the scan document, either of which would break release resolution."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.constants import RETENTION_PROTECTED_FLAG_VALUES
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"

_NOT_A_RELEASE = {"$nin": RETENTION_PROTECTED_FLAG_VALUES}
_RETENTION_DAYS = 30
_RETENTION_ACTION = "delete"
_PROJECT_ID = "p1"
_RELEASE_SCAN_ID = "rel"
_PLAIN_SCAN_ID = "plain"
_RESCAN_ID = "rel-rescan"
_ENVIRONMENT = "production"
_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_EXPIRED_AT = _NOW - timedelta(days=365)


class _EmptyCursor:
    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration


def _patch_common(monkeypatch, db, settings_obj):
    monkeypatch.setattr(f"{MODULE}.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr(
        f"{MODULE}.SystemSettingsRepository", lambda _db: MagicMock(get=AsyncMock(return_value=settings_obj))
    )
    monkeypatch.setattr(f"{MODULE}._referenced_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: False)


def _capturing_db(captured):
    db = MagicMock()
    db.scans.find = lambda query, projection=None: (captured.append(query), _EmptyCursor())[1]
    return db


@pytest.mark.asyncio
async def test_global_retention_cursor_excludes_releases(monkeypatch):
    from app.core.housekeeping import run_housekeeping

    captured: list[dict] = []
    db = _capturing_db(captured)

    class _Settings:
        retention_mode = "global"
        global_retention_days = _RETENTION_DAYS
        global_retention_action = _RETENTION_ACTION

    _patch_common(monkeypatch, db, _Settings())

    await run_housekeeping()

    assert captured, "global retention never opened a scan cursor"
    assert captured[0]["is_release"] == _NOT_A_RELEASE, captured[0]


@pytest.mark.asyncio
async def test_project_retention_cursor_excludes_releases(monkeypatch):
    from app.core.housekeeping import run_housekeeping

    captured: list[dict] = []
    db = _capturing_db(captured)

    async def _agg(_pipeline):
        yield {"_id": {"days": _RETENTION_DAYS, "action": _RETENTION_ACTION}, "project_ids": [_PROJECT_ID]}

    db.projects.aggregate = lambda pipeline: _agg(pipeline)

    class _Settings:
        retention_mode = "project"

    _patch_common(monkeypatch, db, _Settings())

    await run_housekeeping()

    assert any(q.get("is_release") == _NOT_A_RELEASE for q in captured), captured


def _expired_scan(scan_id: str, **overrides) -> dict:
    doc = {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "status": "completed",
        "created_at": _EXPIRED_AT,
    }
    doc.update(overrides)
    return doc


async def _retention_store(scans: list[dict], release_scan_ids: list[str]) -> FakeDatabase:
    db = FakeDatabase()
    await db.system_settings.insert_one(
        {
            "_id": "current",
            "retention_mode": "global",
            "global_retention_days": _RETENTION_DAYS,
            "global_retention_action": _RETENTION_ACTION,
        }
    )
    for scan in scans:
        await db.scans.insert_one(scan)
    for scan_id in release_scan_ids:
        await db.releases.insert_one(
            {
                "_id": f"row-{scan_id}",
                "project_id": _PROJECT_ID,
                "environment": _ENVIRONMENT,
                "scan_id": scan_id,
                "released_at": _NOW,
            }
        )
    return db


async def _run_retention(db: FakeDatabase, monkeypatch) -> list[str]:
    from app.core.housekeeping import run_housekeeping

    monkeypatch.setattr(f"{MODULE}.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: False)
    await run_housekeeping()
    return sorted(doc["_id"] for doc in await db.scans.find({}).to_list(None))


@pytest.mark.asyncio
async def test_a_release_row_without_the_flag_survives_retention(monkeypatch):
    """The mark writes the row and the flag in two steps; a lost second step must not cost the scan."""
    db = await _retention_store(
        [_expired_scan(_RELEASE_SCAN_ID, is_release=False), _expired_scan(_PLAIN_SCAN_ID)],
        [_RELEASE_SCAN_ID],
    )

    assert await _run_retention(db, monkeypatch) == [_RELEASE_SCAN_ID]


@pytest.mark.asyncio
async def test_the_rescan_a_release_resolves_to_survives_retention(monkeypatch):
    """The exemption's unit is the release's live analysis chain: losing the rescan silently moves
    the release's answer back to the numbers the marked scan shipped with."""
    db = await _retention_store(
        [
            _expired_scan(_RELEASE_SCAN_ID, is_release=True, latest_rescan_id=_RESCAN_ID),
            _expired_scan(_RESCAN_ID, is_rescan=True, original_scan_id=_RELEASE_SCAN_ID),
        ],
        [_RELEASE_SCAN_ID],
    )

    assert await _run_retention(db, monkeypatch) == sorted([_RELEASE_SCAN_ID, _RESCAN_ID])


@pytest.mark.asyncio
async def test_a_superseded_rescan_is_not_protected_by_the_release(monkeypatch):
    """Only the link the chain walk reaches is the current analysis; an overwritten one is history."""
    superseded = f"{_RESCAN_ID}-old"
    db = await _retention_store(
        [
            _expired_scan(_RELEASE_SCAN_ID, is_release=True, latest_rescan_id=_RESCAN_ID),
            _expired_scan(_RESCAN_ID, is_rescan=True, original_scan_id=_RELEASE_SCAN_ID),
            _expired_scan(superseded, is_rescan=True, original_scan_id=_RELEASE_SCAN_ID),
        ],
        [_RELEASE_SCAN_ID],
    )

    assert await _run_retention(db, monkeypatch) == sorted([_RELEASE_SCAN_ID, _RESCAN_ID])


def _patch_archive_deps(monkeypatch, archive_module):
    monkeypatch.setattr(archive_module, "is_archive_enabled", lambda: True)
    monkeypatch.setattr(
        archive_module, "ArchiveMetadataRepository", lambda _db: MagicMock(find_by_scan_id=AsyncMock(return_value=None))
    )
    monkeypatch.setattr(
        archive_module,
        "DistributedLocksRepository",
        lambda _db: MagicMock(acquire_lock=AsyncMock(return_value=True), release_lock=AsyncMock()),
    )


async def _archive_db(scan_doc: dict, release_rows: list[dict]) -> FakeDatabase:
    db = FakeDatabase()
    await db.scans.insert_one(scan_doc)
    for row in release_rows:
        await db.releases.insert_one(row)
    return db


def _release_row(scan_id: str) -> dict:
    return {
        "_id": f"row-{scan_id}",
        "project_id": _PROJECT_ID,
        "environment": _ENVIRONMENT,
        "scan_id": scan_id,
        "released_at": _NOW,
    }


@pytest.mark.asyncio
async def test_archive_refuses_a_scan_a_release_row_names(monkeypatch):
    """The row decides, not the flag: the mark writes them separately and either can be the one lost."""
    from app.services import archive as archive_module

    _patch_archive_deps(monkeypatch, archive_module)

    db = await _archive_db({"_id": _RELEASE_SCAN_ID, "project_id": _PROJECT_ID}, [_release_row(_RELEASE_SCAN_ID)])
    upload = AsyncMock()
    monkeypatch.setattr(archive_module, "_upload_archive_bundle", upload)

    assert await archive_module.archive_scan(db, _RELEASE_SCAN_ID) is None
    upload.assert_not_awaited()


@pytest.mark.asyncio
async def test_archive_refuses_the_rescan_a_release_currently_resolves_to(monkeypatch):
    from app.services import archive as archive_module

    _patch_archive_deps(monkeypatch, archive_module)

    db = await _archive_db(
        {"_id": _RESCAN_ID, "project_id": _PROJECT_ID, "is_rescan": True, "original_scan_id": _RELEASE_SCAN_ID},
        [_release_row(_RELEASE_SCAN_ID)],
    )
    await db.scans.insert_one(
        {"_id": _RELEASE_SCAN_ID, "project_id": _PROJECT_ID, "latest_rescan_id": _RESCAN_ID, "is_release": True}
    )
    upload = AsyncMock()
    monkeypatch.setattr(archive_module, "_upload_archive_bundle", upload)

    assert await archive_module.archive_scan(db, _RESCAN_ID) is None
    upload.assert_not_awaited()


@pytest.mark.asyncio
async def test_archive_accepts_a_scan_no_release_row_names(monkeypatch):
    from app.services import archive as archive_module

    _patch_archive_deps(monkeypatch, archive_module)

    db = await _archive_db({"_id": _PLAIN_SCAN_ID, "project_id": _PROJECT_ID}, [_release_row(_RELEASE_SCAN_ID)])
    upload = AsyncMock(return_value=None)
    monkeypatch.setattr(archive_module, "_upload_archive_bundle", upload)

    await archive_module.archive_scan(db, _PLAIN_SCAN_ID)

    upload.assert_awaited_once()
