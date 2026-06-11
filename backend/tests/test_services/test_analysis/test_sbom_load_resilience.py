"""SBOM GridFS load resilience.

Covers the read-your-writes fix: a freshly-uploaded SBOM read via the global
``secondaryPreferred`` preference could be momentarily missing (replication lag), which
made the whole analysis abort yet the scan was still marked ``completed``. The fix reads
the primary with a bounded retry and marks the scan ``failed`` when no SBOM could be loaded.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.db.mongodb import open_gridfs_download_with_retry
from app.services.analysis.engine import _all_sbom_loads_failed, _finalize_scan_and_project


class TestOpenGridfsDownloadWithRetry:
    def test_retries_then_succeeds(self):
        # Two transient misses (file not replicated yet) then success.
        fs = SimpleNamespace(
            open_download_stream=AsyncMock(
                side_effect=[RuntimeError("no file"), RuntimeError("no file"), "STREAM"]
            )
        )
        result = asyncio.run(open_gridfs_download_with_retry(fs, "oid", attempts=4, base_delay=0))
        assert result == "STREAM"
        assert fs.open_download_stream.await_count == 3

    def test_raises_after_exhausting_attempts(self):
        fs = SimpleNamespace(open_download_stream=AsyncMock(side_effect=RuntimeError("still no file")))
        with pytest.raises(RuntimeError, match="still no file"):
            asyncio.run(open_gridfs_download_with_retry(fs, "oid", attempts=3, base_delay=0))
        assert fs.open_download_stream.await_count == 3


def _finding(desc: str) -> SimpleNamespace:
    return SimpleNamespace(description=desc)


class TestAllSbomLoadsFailed:
    def test_all_gridfs_failed_returns_true(self):
        sboms = [{"type": "gridfs_reference", "gridfs_id": "a"}]
        findings = [_finding("Scanner 'system' failed: Failed to load SBOM from GridFS: no file")]
        assert _all_sbom_loads_failed(sboms, findings) is True

    def test_partial_failure_returns_false(self):
        # 2 GridFS SBOMs expected, only 1 failed -> the scan still analysed something.
        sboms = [
            {"type": "gridfs_reference", "gridfs_id": "a"},
            {"type": "gridfs_reference", "gridfs_id": "b"},
        ]
        findings = [_finding("Failed to load SBOM from GridFS: no file")]
        assert _all_sbom_loads_failed(sboms, findings) is False

    def test_no_gridfs_refs_returns_false(self):
        assert _all_sbom_loads_failed([{"bomFormat": "CycloneDX"}], []) is False

    def test_gridfs_but_no_load_failure_returns_false(self):
        sboms = [{"type": "gridfs_reference", "gridfs_id": "a"}]
        assert _all_sbom_loads_failed(sboms, [_finding("some unrelated finding")]) is False


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
                "scan-1", scan_doc, "proj-1", 1, 0, self._stats(), {"status": "failed"},
                scan_repo, project_repo,
                status="failed", error="SBOM could not be loaded for analysis",
            )
        )

        scan_set = scan_update.await_args.args[1]["$set"]
        assert scan_set["status"] == "failed"
        assert scan_set["error"] == "SBOM could not be loaded for analysis"
        # A failed scan must NOT become the project's latest scan / overwrite its stats.
        project_update.assert_not_awaited()

    def test_completed_status_updates_project(self):
        project_update = AsyncMock()
        scan_repo = SimpleNamespace(update_raw=AsyncMock())
        project_repo = SimpleNamespace(update_raw=project_update)
        scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None)

        asyncio.run(
            _finalize_scan_and_project(
                "scan-1", scan_doc, "proj-1", 5, 0, self._stats(), {"status": "completed"},
                scan_repo, project_repo,
            )
        )

        scan_set = scan_repo.update_raw.await_args.args[1]["$set"]
        assert scan_set["status"] == "completed"
        assert "error" not in scan_set
        project_update.assert_awaited_once()
