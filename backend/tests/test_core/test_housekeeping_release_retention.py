"""A release must survive retention: the delete path drops nine collections plus GridFS, and the
archive path removes the scan document, either of which would break release resolution."""

from unittest.mock import AsyncMock, MagicMock

import pytest

MODULE = "app.core.housekeeping"

_NOT_A_RELEASE = {"$ne": True}
_RETENTION_DAYS = 30
_RETENTION_ACTION = "delete"
_PROJECT_ID = "p1"
_RELEASE_SCAN_ID = "rel"
_PLAIN_SCAN_ID = "plain"


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
    monkeypatch.setattr(f"{MODULE}._get_referenced_scan_ids", AsyncMock(return_value=[]))
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


@pytest.mark.asyncio
async def test_archive_refuses_a_release_scan(monkeypatch):
    from app.services import archive as archive_module

    _patch_archive_deps(monkeypatch, archive_module)

    db = MagicMock()
    db.scans.find_one = AsyncMock(return_value={"_id": _RELEASE_SCAN_ID, "project_id": _PROJECT_ID, "is_release": True})
    upload = AsyncMock()
    monkeypatch.setattr(archive_module, "_upload_archive_bundle", upload)

    assert await archive_module.archive_scan(db, _RELEASE_SCAN_ID) is None
    upload.assert_not_awaited()


@pytest.mark.asyncio
async def test_archive_still_accepts_a_scan_with_no_release_flag(monkeypatch):
    """Tri-state: a document predating the flag carries no is_release and is not a release."""
    from app.services import archive as archive_module

    _patch_archive_deps(monkeypatch, archive_module)

    db = MagicMock()
    db.scans.find_one = AsyncMock(return_value={"_id": _PLAIN_SCAN_ID, "project_id": _PROJECT_ID})
    upload = AsyncMock(return_value=None)
    monkeypatch.setattr(archive_module, "_upload_archive_bundle", upload)

    await archive_module.archive_scan(db, _PLAIN_SCAN_ID)

    upload.assert_awaited_once()
