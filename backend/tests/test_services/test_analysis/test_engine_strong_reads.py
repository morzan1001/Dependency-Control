"""Engine read-after-write paths must use strong reads, and missing scans must terminate cleanly."""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from app.services.analysis.engine import _check_race_condition, run_analysis


class TestCheckRaceCondition:
    def test_uses_strong_read(self):
        scan_repo = SimpleNamespace(
            get_by_id_strong=AsyncMock(return_value=None),
            get_by_id=AsyncMock(side_effect=AssertionError("must use get_by_id_strong, not get_by_id")),
        )

        result = asyncio.run(
            _check_race_condition("scan-1", datetime.now(timezone.utc), scan_repo),  # type: ignore[arg-type]
        )

        scan_repo.get_by_id_strong.assert_awaited_once_with("scan-1")
        scan_repo.get_by_id.assert_not_awaited()
        assert result is False


class TestRunAnalysisScanNotFound:
    """A missing scan must terminate cleanly so the worker's retry path stops re-queueing it."""

    def test_marks_scan_failed_and_returns_false(self, monkeypatch):
        update_raw = AsyncMock()

        def _scan_repo(_db):
            return SimpleNamespace(
                get_by_id_strong=AsyncMock(return_value=None),
                update_raw=update_raw,
            )

        monkeypatch.setattr("app.services.analysis.engine.ScanRepository", _scan_repo)
        monkeypatch.setattr("app.services.analysis.engine.AnalysisResultRepository", lambda _: MagicMock())
        monkeypatch.setattr("app.services.analysis.engine.FindingRepository", lambda _: MagicMock())
        monkeypatch.setattr("app.services.analysis.engine.CallgraphRepository", lambda _: MagicMock())
        monkeypatch.setattr("app.services.analysis.engine.ProjectRepository", lambda _: MagicMock())

        result = asyncio.run(run_analysis("missing-scan", [], [], MagicMock()))

        assert result is False
        update_raw.assert_awaited_once()
        scan_id_arg, update_doc = update_raw.await_args.args
        assert scan_id_arg == "missing-scan"
        assert update_doc["$set"]["status"] == "failed"
