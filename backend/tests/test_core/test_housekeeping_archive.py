"""Tests for housekeeping archive integration.

Tests the archive branch in retention logic: _archive_scans_and_delete,
_handle_retention_action, and run_housekeeping with archive mode.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.housekeeping import (
    _archive_scans_and_delete,
    _handle_retention_action,
)
from app.models.archive import ArchiveMetadata

MODULE = "app.core.housekeeping"
# archive_scan is lazy-imported inside _archive_scans_and_delete,
# so we patch it at its source module
ARCHIVE_SVC = "app.services.archive"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_archive_metadata(scan_id="scan-1"):
    return ArchiveMetadata(
        project_id="proj-1",
        scan_id=scan_id,
        s3_key=f"proj-1/{scan_id}.json.gz",
        s3_bucket="dc-archives",
    )


# ---------------------------------------------------------------------------
# _archive_scans_and_delete
# ---------------------------------------------------------------------------


class TestArchiveScansAndDelete:
    def test_returns_zero_for_empty_list(self):
        result = asyncio.run(_archive_scans_and_delete(MagicMock(), [], "test"))
        assert result == 0

    def test_archives_and_deletes_successfully(self):
        metadata = _make_archive_metadata()

        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=metadata) as mock_archive,
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock, return_value=1),
        ):
            result = asyncio.run(_archive_scans_and_delete(MagicMock(), ["scan-1"], "test"))

        assert result == 1
        mock_archive.assert_called_once()

    def test_skips_delete_for_failed_archives(self):
        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=None) as mock_archive,
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock, return_value=0) as mock_delete,
        ):
            result = asyncio.run(_archive_scans_and_delete(MagicMock(), ["scan-1"], "test"))

        assert result == 0
        mock_archive.assert_called_once()
        # Delete should be called with empty list (failed scans excluded)
        call_args = mock_delete.call_args[0]
        assert call_args[1] == []  # No scans to delete

    def test_partial_failure_only_deletes_successful(self):
        # scan-1 archives ok, scan-2 fails
        async def mock_archive_fn(db, scan_id):
            await asyncio.sleep(0)
            if scan_id == "scan-1":
                return _make_archive_metadata(scan_id="scan-1")
            return None

        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, side_effect=mock_archive_fn),
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock, return_value=1) as mock_delete,
        ):
            result = asyncio.run(_archive_scans_and_delete(MagicMock(), ["scan-1", "scan-2"], "test"))

        assert result == 1
        # Only scan-1 should be in the delete list
        call_args = mock_delete.call_args[0]
        assert "scan-1" in call_args[1]
        assert "scan-2" not in call_args[1]

    def test_handles_archive_exception(self):
        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, side_effect=Exception("Archive crashed")),
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock, return_value=0) as mock_delete,
        ):
            result = asyncio.run(_archive_scans_and_delete(MagicMock(), ["scan-1"], "test"))

        assert result == 0
        call_args = mock_delete.call_args[0]
        assert call_args[1] == []  # No scans to delete

    def test_processes_all_provided_scan_ids(self):
        # _process_scans_in_batches is responsible for chunking; _archive_scans_and_delete
        # must process every ID it receives (no internal slicing).
        scan_ids = [f"scan-{i}" for i in range(100)]
        metadata = _make_archive_metadata()

        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=metadata) as mock_archive,
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock, return_value=100),
        ):
            asyncio.run(_archive_scans_and_delete(MagicMock(), scan_ids, "test"))

        assert mock_archive.call_count == 100


# ---------------------------------------------------------------------------
# _handle_retention_action
# ---------------------------------------------------------------------------


class TestHandleRetentionAction:
    def test_delete_action_calls_delete(self):
        with patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock) as mock_delete:
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "delete", "test"))

        mock_delete.assert_called_once()

    def test_archive_action_with_s3_enabled_calls_archive(self):
        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=True),
            patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive,
        ):
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "archive", "test"))

        mock_archive.assert_called_once()

    def test_archive_action_without_s3_logs_warning(self):
        with (
            patch(f"{MODULE}.is_archive_enabled", return_value=False),
            patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive,
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock) as mock_delete,
            patch(f"{MODULE}.logger") as mock_logger,
        ):
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "archive", "test"))

        mock_archive.assert_not_called()
        mock_delete.assert_not_called()
        mock_logger.warning.assert_called_once()

    def test_none_action_does_nothing(self):
        with (
            patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive,
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock) as mock_delete,
        ):
            asyncio.run(_handle_retention_action(MagicMock(), ["scan-1"], "none", "test"))

        mock_archive.assert_not_called()
        mock_delete.assert_not_called()

    def test_empty_scan_list_returns_early(self):
        with (
            patch(f"{MODULE}._archive_scans_and_delete", new_callable=AsyncMock) as mock_archive,
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock) as mock_delete,
        ):
            asyncio.run(_handle_retention_action(MagicMock(), [], "delete", "test"))

        mock_archive.assert_not_called()
        mock_delete.assert_not_called()


# ---------------------------------------------------------------------------
# run_housekeeping (global mode with archive)
# ---------------------------------------------------------------------------


class TestRunHousekeepingArchive:
    def test_global_mode_with_archive_action(self):
        from app.core.housekeeping import run_housekeeping

        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "archive"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        # Mock the cursor for scan IDs (async iteration)
        mock_scan_doc = {"_id": "scan-1"}
        mock_cursor = MagicMock()

        # Make cursor async iterable
        async def async_iter():
            yield mock_scan_doc

        mock_cursor.__aiter__ = lambda self: async_iter()
        mock_db = MagicMock()
        mock_db.scans.find = MagicMock(return_value=mock_cursor)

        with (
            patch(f"{MODULE}.get_database", new_callable=AsyncMock, return_value=mock_db),
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._get_referenced_scan_ids", new_callable=AsyncMock, return_value=[]),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(run_housekeeping())

        mock_handle.assert_called_once()
        call_args = mock_handle.call_args
        assert call_args[0][2] == "archive"  # action argument

    def test_global_mode_none_action_skips_cleanup(self):
        from app.core.housekeeping import run_housekeeping

        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "none"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        with (
            patch(f"{MODULE}.get_database", new_callable=AsyncMock, return_value=MagicMock()),
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(run_housekeeping())

        # retention_action is "none" but retention_days > 0, so it enters the block
        # but the condition `retention_action != "none"` in run_housekeeping prevents it
        mock_handle.assert_not_called()

    def test_global_mode_excludes_pinned_scans(self):
        from app.core.housekeeping import run_housekeeping

        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 30
        mock_settings.global_retention_action = "archive"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        mock_scan_doc = {"_id": "scan-1"}
        mock_cursor = MagicMock()

        async def async_iter():
            yield mock_scan_doc

        mock_cursor.__aiter__ = lambda self: async_iter()
        mock_db = MagicMock()
        mock_db.scans.find = MagicMock(return_value=mock_cursor)

        with (
            patch(f"{MODULE}.get_database", new_callable=AsyncMock, return_value=mock_db),
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._get_referenced_scan_ids", new_callable=AsyncMock, return_value=[]),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock),
        ):
            asyncio.run(run_housekeeping())

        # Verify the query includes "pinned": {"$ne": True}
        find_call = mock_db.scans.find.call_args
        query = find_call[0][0]
        assert "pinned" in query
        assert query["pinned"] == {"$ne": True}

    def test_global_mode_zero_retention_days_skips(self):
        from app.core.housekeeping import run_housekeeping

        mock_settings = MagicMock()
        mock_settings.retention_mode = "global"
        mock_settings.global_retention_days = 0
        mock_settings.global_retention_action = "delete"

        mock_repo = MagicMock()
        mock_repo.get = AsyncMock(return_value=mock_settings)

        with (
            patch(f"{MODULE}.get_database", new_callable=AsyncMock, return_value=MagicMock()),
            patch(f"{MODULE}.SystemSettingsRepository", return_value=mock_repo),
            patch(f"{MODULE}._handle_retention_action", new_callable=AsyncMock) as mock_handle,
        ):
            asyncio.run(run_housekeeping())

        mock_handle.assert_not_called()


# ---------------------------------------------------------------------------
# Status filter tests (in-progress scan exclusion)
# ---------------------------------------------------------------------------


import pytest


@pytest.mark.asyncio
async def test_housekeeping_global_skips_in_progress_scans(monkeypatch):
    """Global retention cursor must exclude scans with status pending/processing."""
    from datetime import datetime, timezone
    from app.core.housekeeping import run_housekeeping

    captured_queries: list[dict] = []

    db = MagicMock()

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
    monkeypatch.setattr("app.core.housekeeping._get_referenced_scan_ids", AsyncMock(return_value=[]))
    monkeypatch.setattr("app.core.housekeeping.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)

    await run_housekeeping()

    assert len(captured_queries) >= 1
    q = captured_queries[0]
    assert "status" in q, f"Expected status filter in query, got: {q}"
    assert q["status"] == {"$nin": ["pending", "processing"]}


@pytest.mark.asyncio
async def test_housekeeping_project_specific_skips_in_progress_scans(monkeypatch):
    """Project-specific retention cursor must also exclude pending/processing scans."""
    from app.core.housekeeping import run_housekeeping

    captured_queries: list[dict] = []

    db = MagicMock()

    class _EmptyCursor:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    def find_capture(query, projection=None):
        captured_queries.append(query)
        return _EmptyCursor()

    db.scans.find = find_capture

    # Aggregate yields one group
    async def _agg_iter(_pipeline):
        yield {
            "_id": {"days": 30, "action": "delete"},
            "project_ids": ["proj-1"],
        }

    db.projects.aggregate = lambda pipeline: _agg_iter(pipeline)

    class _SystemSettings:
        retention_mode = "project"
        global_retention_days = 0
        global_retention_action = "none"

    settings_repo = MagicMock()
    settings_repo.get = AsyncMock(return_value=_SystemSettings())

    monkeypatch.setattr("app.core.housekeeping.SystemSettingsRepository", lambda _db: settings_repo)
    monkeypatch.setattr("app.core.housekeeping._get_referenced_scan_ids", AsyncMock(return_value=[]))
    monkeypatch.setattr("app.core.housekeeping.get_database", AsyncMock(return_value=db))
    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)

    await run_housekeeping()

    assert any("status" in q and q["status"] == {"$nin": ["pending", "processing"]} for q in captured_queries), (
        f"Expected status filter in at least one cursor query, got: {captured_queries}"
    )


@pytest.mark.asyncio
async def test_reap_orphan_s3_objects_deletes_only_old_unknown_keys(monkeypatch):
    """Reaper deletes S3 objects that have no archive_metadata record AND are older than min age."""
    from datetime import datetime, timezone, timedelta

    from app.core.housekeeping import _reap_orphan_s3_objects

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(hours=48)
    recent_time = now - timedelta(hours=2)

    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: True)
    monkeypatch.setattr(
        "app.core.housekeeping.list_objects",
        AsyncMock(
            return_value=[
                {"Key": "p1/scan-orphan-old.bundle", "Size": 100, "LastModified": old_time},
                {"Key": "p1/scan-orphan-recent.bundle", "Size": 100, "LastModified": recent_time},
                {"Key": "p1/scan-known.bundle", "Size": 100, "LastModified": old_time},
            ]
        ),
    )

    delete_calls: list[str] = []

    async def fake_delete(key, **kw):
        delete_calls.append(key)

    monkeypatch.setattr("app.core.housekeeping.delete_object", fake_delete)

    db = MagicMock()

    async def metadata_cursor(*_args, **_kwargs):
        yield {"s3_key": "p1/scan-known.bundle"}

    db.archive_metadata.find = lambda *a, **kw: metadata_cursor()

    reaped = await _reap_orphan_s3_objects(db)

    assert reaped == 1
    assert delete_calls == ["p1/scan-orphan-old.bundle"]


@pytest.mark.asyncio
async def test_reap_orphan_skips_when_archive_disabled(monkeypatch):
    from app.core.housekeeping import _reap_orphan_s3_objects

    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: False)
    # list_objects should NOT be called
    list_calls = []
    monkeypatch.setattr(
        "app.core.housekeeping.list_objects",
        AsyncMock(side_effect=lambda *a, **kw: list_calls.append(1)),
    )

    db = MagicMock()
    reaped = await _reap_orphan_s3_objects(db)
    assert reaped == 0
    assert list_calls == []


@pytest.mark.asyncio
async def test_reap_orphan_tolerates_list_failure(monkeypatch):
    """If list_objects raises, the reaper returns 0 (best-effort) without re-raising."""
    from app.core.housekeeping import _reap_orphan_s3_objects

    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: True)
    monkeypatch.setattr(
        "app.core.housekeeping.list_objects",
        AsyncMock(side_effect=RuntimeError("S3 unavailable")),
    )

    db = MagicMock()
    reaped = await _reap_orphan_s3_objects(db)
    assert reaped == 0


# ---------------------------------------------------------------------------
# Regression tests for follow-up review bug #8
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reap_stale_metadata_drops_entries_for_restored_scans(monkeypatch):
    """Bug #8: archive_metadata entries whose scan_id lives in db.scans are stale and must be reaped."""
    from app.core.housekeeping import _reap_stale_metadata

    db = MagicMock()

    # Two metadata entries: one whose scan exists (stale), one whose scan doesn't (still valid)
    stale_meta = {"_id": "meta-stale", "scan_id": "scan-restored"}
    valid_meta = {"_id": "meta-valid", "scan_id": "scan-archived"}

    async def metadata_cursor(*_args, **_kwargs):
        yield stale_meta
        yield valid_meta

    db.archive_metadata.find = lambda *a, **kw: metadata_cursor()

    async def scans_find_one(query, *_args, **_kwargs):
        # Only the restored scan exists in db.scans
        if query.get("_id") == "scan-restored":
            return {"_id": "scan-restored"}
        return None

    db.scans.find_one = scans_find_one

    delete_calls: list[dict] = []

    async def fake_delete_one(query):
        delete_calls.append(query)
        result = MagicMock()
        result.deleted_count = 1
        return result

    db.archive_metadata.delete_one = fake_delete_one

    reaped = await _reap_stale_metadata(db)

    assert reaped == 1
    assert delete_calls == [{"_id": "meta-stale"}]


@pytest.mark.asyncio
async def test_reap_orphan_runs_stale_metadata_pass_first(monkeypatch):
    """Bug #8: _reap_orphan_s3_objects must call _reap_stale_metadata before listing S3."""
    from app.core.housekeeping import _reap_orphan_s3_objects

    monkeypatch.setattr("app.core.housekeeping.is_archive_enabled", lambda: True)

    call_order: list[str] = []

    async def fake_stale_reap(_db):
        call_order.append("stale_metadata")
        return 0

    async def fake_list(*_a, **_kw):
        call_order.append("list_objects")
        return []

    monkeypatch.setattr("app.core.housekeeping._reap_stale_metadata", fake_stale_reap)
    monkeypatch.setattr("app.core.housekeeping.list_objects", fake_list)

    db = MagicMock()

    class _EmptyAsyncGen:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    db.archive_metadata.find = lambda *a, **kw: _EmptyAsyncGen()

    await _reap_orphan_s3_objects(db)

    assert call_order == ["stale_metadata", "list_objects"]
