"""Tests for housekeeping archive integration.

Tests the archive branch in retention logic: _archive_scans_and_delete,
_handle_retention_action, and run_housekeeping with archive mode.
"""

import asyncio
from datetime import datetime, timezone
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
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock, return_value=1) as mock_delete,
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

    def test_respects_batch_size_limit(self):
        scan_ids = [f"scan-{i}" for i in range(100)]
        metadata = _make_archive_metadata()

        with (
            patch(f"{ARCHIVE_SVC}.archive_scan", new_callable=AsyncMock, return_value=metadata) as mock_archive,
            patch(f"{MODULE}._delete_scans_and_related_data", new_callable=AsyncMock, return_value=50),
            patch(f"{MODULE}.ARCHIVE_BATCH_SIZE", 50),
        ):
            asyncio.run(_archive_scans_and_delete(MagicMock(), scan_ids, "test"))

        # Should only process ARCHIVE_BATCH_SIZE scans
        assert mock_archive.call_count == 50


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
