"""SBOM GridFS load resilience: primary read with bounded retry, marking the scan failed when no SBOM loads."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.db.mongodb import open_gridfs_download_with_retry
from app.services.analysis.engine import _finalize_scan_and_project


class TestOpenGridfsDownloadWithRetry:
    def test_retries_then_succeeds(self):
        # two transient misses (file not replicated yet) then success
        fs = SimpleNamespace(
            open_download_stream=AsyncMock(side_effect=[RuntimeError("no file"), RuntimeError("no file"), "STREAM"])
        )
        result = asyncio.run(open_gridfs_download_with_retry(fs, "oid", attempts=4, base_delay=0))
        assert result == "STREAM"
        assert fs.open_download_stream.await_count == 3

    def test_raises_after_exhausting_attempts(self):
        fs = SimpleNamespace(open_download_stream=AsyncMock(side_effect=RuntimeError("still no file")))
        with pytest.raises(RuntimeError, match="still no file"):
            asyncio.run(open_gridfs_download_with_retry(fs, "oid", attempts=3, base_delay=0))
        assert fs.open_download_stream.await_count == 3


class TestFinalizeMarksFailed:
    def _stats(self):
        return SimpleNamespace(model_dump=lambda: {"x": 1})

    def test_failed_status_persisted_and_project_not_clobbered(self):
        scan_update = AsyncMock()
        project_update = AsyncMock()
        scan_repo = SimpleNamespace(update_raw=scan_update)
        project_repo = SimpleNamespace(update_raw=project_update)
        scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None)

        asyncio.run(
            _finalize_scan_and_project(
                "scan-1",
                scan_doc,
                "proj-1",
                1,
                0,
                self._stats(),
                {"status": "failed"},
                scan_repo,
                project_repo,
                status="failed",
                error="SBOM could not be loaded for analysis",
            )
        )

        scan_set = scan_update.await_args.args[1]["$set"]
        assert scan_set["status"] == "failed"
        assert scan_set["error"] == "SBOM could not be loaded for analysis"
        # a failed scan must not become the project's latest scan or overwrite its stats
        project_update.assert_not_awaited()

    def test_completed_status_updates_project(self):
        project_update = AsyncMock()
        scan_repo = SimpleNamespace(update_raw=AsyncMock())
        # no latest scan yet -> guard allows the update
        project_repo = SimpleNamespace(
            update_raw=project_update,
            get_by_id_strong=AsyncMock(return_value=SimpleNamespace(latest_scan_id=None)),
        )
        scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None)

        asyncio.run(
            _finalize_scan_and_project(
                "scan-1",
                scan_doc,
                "proj-1",
                5,
                0,
                self._stats(),
                {"status": "completed"},
                scan_repo,
                project_repo,
            )
        )

        scan_set = scan_repo.update_raw.await_args.args[1]["$set"]
        assert scan_set["status"] == "completed"
        assert "error" not in scan_set
        project_update.assert_awaited_once()
