"""A missing scan must terminate cleanly."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from app.services.analysis.engine import run_analysis


class TestRunAnalysisScanNotFound:
    """A missing scan must terminate cleanly so the worker's retry path stops re-queueing it."""

    def test_marks_scan_failed_and_returns_false(self, monkeypatch):
        update_raw = AsyncMock()

        def _scan_repo(_db):
            return SimpleNamespace(
                get_by_id=AsyncMock(return_value=None),
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
