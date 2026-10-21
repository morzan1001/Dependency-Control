import asyncio
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import ARCHIVE_BATCH_SIZE, RETENTION_PROTECTED_FLAG_VALUES
from app.core.housekeeping import (
    _archive_scans_and_delete,
    _expire_group,
    _handle_retention_action,
    _retention_can_act,
    _run_retention,
)
from app.models.archive import ArchiveMetadata
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"
# archive_scan is lazy-imported inside _archive_scans_and_delete, so patch it at its source module.
ARCHIVE_SVC = "app.services.archive"


def _mock_db() -> MagicMock:
    """A mock database with a working lock collection, so retention gets past taking its lock."""
    db = MagicMock()
    db.distributed_locks = FakeDatabase().distributed_locks
    return db


async def _store_with(*scan_ids: str) -> FakeDatabase:
    db = FakeDatabase()
    for scan_id in scan_ids:
        await db.scans.insert_one({"_id": scan_id, "status": "completed"})
    return db


async def _remaining(db: FakeDatabase) -> set[str]:
    return {doc["_id"] async for doc in db.scans.find({})}


def _make_archive_metadata(scan_id="scan-1"):
    return ArchiveMetadata(
        project_id="proj-1",
        scan_id=scan_id,
        s3_key=f"proj-1/{scan_id}.json.gz",
        s3_bucket="dc-archives",
    )


class TestArchiveScansAndDelete:
    @pytest.mark.asyncio
    async def test_archives_and_deletes_successfully(self):
        db = await _store_with("scan-1")
        metadata = _make_archive_metadata()

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=metadata) as mock_archive:
            await _archive_scans_and_delete(db, ["scan-1"], "test")

        mock_archive.assert_called_once()
        assert await _remaining(db) == set()

    @pytest.mark.asyncio
    async def test_skips_delete_for_failed_archives(self):
        db = await _store_with("scan-1")

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=None) as mock_archive:
            await _archive_scans_and_delete(db, ["scan-1"], "test")

        mock_archive.assert_called_once()
        assert await _remaining(db) == {"scan-1"}

    @pytest.mark.asyncio
    async def test_partial_failure_only_deletes_successful(self):
        db = await _store_with("scan-1", "scan-2")

        async def mock_archive_fn(db, scan_id):
            if scan_id == "scan-1":
                return _make_archive_metadata(scan_id="scan-1")
            return None

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, side_effect=mock_archive_fn):
            await _archive_scans_and_delete(db, ["scan-1", "scan-2"], "test")

        assert await _remaining(db) == {"scan-2"}

    @pytest.mark.asyncio
    async def test_handles_archive_exception(self):
        db = await _store_with("scan-1")

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, side_effect=Exception("Archive crashed")):
            await _archive_scans_and_delete(db, ["scan-1"], "test")

        assert await _remaining(db) == {"scan-1"}

    @pytest.mark.asyncio
    async def test_processes_all_provided_scan_ids(self):
        # Chunking is _process_scans_in_batches's job; this must process every ID it receives.
        scan_ids = [f"scan-{i}" for i in range(100)]
        metadata = _make_archive_metadata()

        with patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=metadata) as mock_archive:
            await _archive_scans_and_delete(await _store_with(*scan_ids), scan_ids, "test")

        assert mock_archive.call_count == 100

    @pytest.mark.asyncio
    async def test_the_failure_warning_names_the_first_twenty_scans(self, caplog):
        scan_ids = [f"scan-{i:02d}" for i in range(25)]

        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=None),
            caplog.at_level(logging.WARNING, logger=MODULE),
        ):
            await _archive_scans_and_delete(await _store_with(*scan_ids), scan_ids, "test")

        (warning,) = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
        assert all(scan_id in warning for scan_id in scan_ids[:20])
        assert not any(scan_id in warning for scan_id in scan_ids[20:])
        assert "25 scan(s)" in warning


class TestHandleRetentionAction:
    def test_delete_action_calls_delete(self):
        with patch(f"{MODULE}._delete_expirable", new_callable=AsyncMock) as mock_delete:
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "delete", "test"))

        mock_delete.assert_called_once()

    def test_archive_action_calls_archive(self):
        with patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive:
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "archive", "test"))

        mock_archive.assert_called_once()

    def test_empty_scan_list_returns_early(self):
        with (
            patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive,
            patch(f"{MODULE}._delete_expirable", new_callable=AsyncMock) as mock_delete,
        ):
            asyncio.run(_handle_retention_action(MagicMock(), [], "delete", "test"))

        mock_archive.assert_not_called()
        mock_delete.assert_not_called()


class TestRetentionCanAct:
    @pytest.mark.parametrize(("action", "archive_enabled"), [("delete", False), ("archive", True)])
    def test_an_action_that_expires_scans_can_act(self, action, archive_enabled):
        with patch(f"{MODULE}.is_archive_enabled", return_value=archive_enabled):
            assert _retention_can_act(action, "test") is True

    def test_archive_without_s3_is_reported(self, caplog):
        with patch(f"{MODULE}.is_archive_enabled", return_value=False), caplog.at_level(logging.WARNING, logger=MODULE):
            assert _retention_can_act("archive", "test") is False

        assert "S3 is not configured" in caplog.text

    def test_an_unknown_action_is_reported_by_name(self, caplog):
        """A value stored before the schemas constrained it would otherwise keep every scan forever, unlogged."""
        with caplog.at_level(logging.WARNING, logger=MODULE):
            assert _retention_can_act("Delete", "test") is False

        assert "'Delete'" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["archive", "Delete"], ids=["archive-without-s3", "unknown"])
async def test_an_action_that_cannot_act_walks_no_expired_scan(monkeypatch, caplog, action):
    db = FakeDatabase()
    expired = datetime.now(timezone.utc) - timedelta(days=200)
    for i in range(2 * ARCHIVE_BATCH_SIZE + 1):
        await db.scans.insert_one(
            {"_id": f"scan-{i}", "project_id": "p1", "status": "completed", "created_at": expired}
        )
    unreferenced = AsyncMock(side_effect=lambda _db, batch: [doc["_id"] for doc in batch])
    monkeypatch.setattr(f"{MODULE}._unreferenced", unreferenced)
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: False)

    with caplog.at_level(logging.WARNING, logger=MODULE):
        await _expire_group(db, 90, {}, action, "retention")

    unreferenced.assert_not_called()
    assert len(caplog.records) == 1
    assert await db.scans.count_documents({}) == 2 * ARCHIVE_BATCH_SIZE + 1


class TestRunRetention:
    def test_global_mode_with_archive_action(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "archive"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        mock_cursor = MagicMock()
        mock_cursor.to_list = AsyncMock(return_value=[{"_id": "scan-1"}])
        mock_db = _mock_db()
        mock_db.scans.find = MagicMock(return_value=mock_cursor)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}._referenced_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}.release_protected_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}._project_heads", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(_run_retention(mock_db))

        mock_handle.assert_called_once()
        call_args = mock_handle.call_args
        assert call_args[0][2] == "archive"

    def test_global_mode_none_action_skips_cleanup(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "none"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(_run_retention(_mock_db()))

        # retention_days > 0 enters the block, but action "none" short-circuits _handle_retention_action.
        mock_handle.assert_not_called()

    def test_global_mode_excludes_pinned_scans(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "archive"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        mock_cursor = MagicMock()
        mock_cursor.to_list = AsyncMock(return_value=[{"_id": "scan-1"}])
        mock_db = _mock_db()
        mock_db.scans.find = MagicMock(return_value=mock_cursor)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}._referenced_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}.release_protected_scan_ids", new_callable=AsyncMock, return_value=set()),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock),
        ):
            asyncio.run(_run_retention(mock_db))

        find_call = mock_db.scans.find.call_args
        query = find_call[0][0]
        assert "pinned" in query
        assert query["pinned"] == {"$nin": RETENTION_PROTECTED_FLAG_VALUES}

    def test_global_mode_zero_retention_days_skips(self):
        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 0
        mock_settings.global_retention_action = "delete"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        with (
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(_run_retention(_mock_db()))

        mock_handle.assert_not_called()


@pytest.mark.asyncio
async def test_housekeeping_global_skips_in_progress_scans(monkeypatch):
    captured_queries: list[dict] = []

    db = _mock_db()

    class _EmptyCursor:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    def find_capture(query, projection=None):
        captured_queries.append(query)
        return _EmptyCursor()

    db.scans.find = find_capture

    class _SystemSettings:
        retention_mode = "global"
        global_retention_days = 30
        global_retention_action = "delete"

    settings_repo = MagicMock()
    settings_repo.get = AsyncMock(return_value=_SystemSettings())

    monkeypatch.setattr("app.core.housekeeping.SystemSettingsRepository", lambda _db: settings_repo)
    monkeypatch.setattr("app.core.housekeeping._referenced_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.release_protected_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)

    await _run_retention(db)

    retention_cursors = [q for q in captured_queries if "created_at" in q]
    assert retention_cursors, captured_queries
    for q in retention_cursors:
        assert q["status"] == {"$nin": ["pending", "processing"]}, q


@pytest.mark.asyncio
async def test_housekeeping_project_specific_skips_in_progress_scans(monkeypatch):
    captured_queries: list[dict] = []

    db = _mock_db()

    class _EmptyCursor:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    def find_capture(query, projection=None):
        captured_queries.append(query)
        return _EmptyCursor()

    db.scans.find = find_capture

    async def _agg_iter(_pipeline):
        yield {
            "_id": {"days": 30, "action": "delete"},
            "project_ids": ["proj-1"],
        }

    db.projects.aggregate = _agg_iter

    class _SystemSettings:
        retention_mode = "project"
        global_retention_days = 0
        global_retention_action = "none"

    settings_repo = MagicMock()
    settings_repo.get = AsyncMock(return_value=_SystemSettings())

    monkeypatch.setattr("app.core.housekeeping.SystemSettingsRepository", lambda _db: settings_repo)
    monkeypatch.setattr("app.core.housekeeping._referenced_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.release_protected_scan_ids", AsyncMock(return_value=set()))
    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)

    await _run_retention(db)

    assert any("status" in q and q["status"] == {"$nin": ["pending", "processing"]} for q in captured_queries), (
        f"Expected status filter in at least one cursor query, got: {captured_queries}"
    )


@pytest.mark.asyncio
async def test_reap_orphan_callgraphs_deletes_only_orphans_past_the_age_window():
    """The window protects callgraphs uploaded before their scan row exists; an inverted cutoff destroys them."""
    from datetime import datetime, timedelta, timezone

    from app.core.constants import ORPHAN_MIN_AGE_HOURS
    from app.core.housekeeping import _reap_orphan_callgraphs
    from tests.mocks.fake_mongo import FakeDatabase

    now = datetime.now(timezone.utc)
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "scan-known"})
    await db.callgraphs.insert_many(
        [
            {
                "_id": "cg-orphan-old",
                "scan_id": "scan-missing",
                "created_at": now - timedelta(hours=ORPHAN_MIN_AGE_HOURS * 2),
            },
            {"_id": "cg-orphan-fresh", "scan_id": "scan-arriving", "created_at": now - timedelta(minutes=1)},
            {
                "_id": "cg-known-old",
                "scan_id": "scan-known",
                "created_at": now - timedelta(hours=ORPHAN_MIN_AGE_HOURS * 2),
            },
        ]
    )

    deleted = await _reap_orphan_callgraphs(db)

    survivors = sorted([cg["_id"] async for cg in db.callgraphs.find({})])
    assert deleted == 1
    assert survivors == ["cg-known-old", "cg-orphan-fresh"]


@pytest.mark.asyncio
async def test_reap_orphan_callgraphs_spares_a_fresh_upload_reusing_an_orphaned_scan_id():
    """A retry uploading under an abandoned scan_id right now is still in flight and must survive the sweep."""
    from datetime import datetime, timedelta, timezone

    from app.core.constants import ORPHAN_MIN_AGE_HOURS
    from app.core.housekeeping import _reap_orphan_callgraphs
    from tests.mocks.fake_mongo import FakeDatabase

    now = datetime.now(timezone.utc)
    db = FakeDatabase()
    await db.callgraphs.insert_many(
        [
            {
                "_id": "cg-stale",
                "scan_id": "scan-retried",
                "created_at": now - timedelta(hours=ORPHAN_MIN_AGE_HOURS * 2),
            },
            {"_id": "cg-retry", "scan_id": "scan-retried", "created_at": now - timedelta(minutes=1)},
        ]
    )

    deleted = await _reap_orphan_callgraphs(db)

    survivors = [cg["_id"] async for cg in db.callgraphs.find({})]
    assert deleted == 1
    assert survivors == ["cg-retry"]
