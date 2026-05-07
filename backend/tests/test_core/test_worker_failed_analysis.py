"""Worker race-condition retry handling.

Engine owns status and retry_count writes; the worker only enforces the retry ceiling.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from app.core.worker import AnalysisWorkerManager


def _build_manager() -> AnalysisWorkerManager:
    mgr = AnalysisWorkerManager(num_workers=1)
    mgr.queue = asyncio.Queue()
    return mgr


def _build_db_with_scans(update_one: AsyncMock) -> MagicMock:
    db = MagicMock()
    db.scans = MagicMock()
    db.scans.update_one = update_one
    return db


class TestHandleFailedAnalysis:
    def test_under_limit_requeues_without_writing_retry_count(self):
        mgr = _build_manager()
        mgr._active_scans = {"scan-1"}
        update_one = AsyncMock()
        db = _build_db_with_scans(update_one)
        scan = {"_id": "scan-1", "retry_count": 1}

        terminal = asyncio.run(mgr._handle_failed_analysis(scan, "scan-1", db))

        assert terminal is False
        assert mgr.queue.qsize() == 1
        assert mgr.queue.get_nowait() == "scan-1"
        assert "scan-1" not in mgr._active_scans
        update_one.assert_not_awaited()

    def test_at_limit_marks_failed_and_does_not_requeue(self):
        mgr = _build_manager()
        mgr._active_scans = {"scan-1"}
        update_one = AsyncMock()
        db = _build_db_with_scans(update_one)
        # retry_count=4 in snapshot + 1 (engine inc) = 5, hits ceiling.
        scan = {"_id": "scan-1", "retry_count": 4}

        terminal = asyncio.run(mgr._handle_failed_analysis(scan, "scan-1", db))

        assert terminal is True
        assert mgr.queue.qsize() == 0
        update_one.assert_awaited_once()
        args, _ = update_one.await_args
        assert args[0] == {"_id": "scan-1"}
        assert args[1]["$set"]["status"] == "failed"

    def test_does_not_double_increment_retry_count(self):
        mgr = _build_manager()
        mgr._active_scans = {"scan-1"}
        update_one = AsyncMock()
        db = _build_db_with_scans(update_one)
        scan = {"_id": "scan-1", "retry_count": 0}

        asyncio.run(mgr._handle_failed_analysis(scan, "scan-1", db))

        for call in update_one.await_args_list:
            update_doc = call.args[1] if len(call.args) > 1 else call.kwargs.get("update")
            assert "$inc" not in (update_doc or {}), f"unexpected $inc: {update_doc}"
