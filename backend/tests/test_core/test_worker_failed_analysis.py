"""Worker retry handling: the engine owns status/retry_count writes; the worker only enforces the ceiling."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.worker import AnalysisWorkerManager


def _build_manager() -> AnalysisWorkerManager:
    mgr = AnalysisWorkerManager(num_workers=1)
    mgr.queue = asyncio.Queue()
    return mgr


def _build_db_with_scans(update_one: AsyncMock, project: dict | None = None) -> MagicMock:
    db = MagicMock()
    db.scans = MagicMock()
    db.scans.update_one = update_one
    db.projects = MagicMock()
    db.projects.find_one = AsyncMock(return_value=project)
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

    def test_at_limit_emits_analysis_failed_webhook_and_notification(self):
        mgr = _build_manager()
        mgr._active_scans = {"scan-1"}
        update_one = AsyncMock()
        project = {"_id": "proj-1", "name": "My Project"}
        db = _build_db_with_scans(update_one, project=project)
        scan = {"_id": "scan-1", "project_id": "proj-1", "retry_count": 4}

        with (
            patch("app.core.worker.webhook_service.trigger_analysis_failed", new=AsyncMock()) as trigger,
            patch("app.core.worker.safe_notify_project_event", new=AsyncMock()) as notify,
        ):
            terminal = asyncio.run(mgr._handle_failed_analysis(scan, "scan-1", db))

        assert terminal is True
        trigger.assert_awaited_once()
        _, tkw = trigger.await_args
        assert tkw["scan_id"] == "scan-1"
        assert tkw["project_id"] == "proj-1"
        assert tkw["project_name"] == "My Project"
        assert "retry attempts" in tkw["error_message"]
        notify.assert_awaited_once()
        _, nkw = notify.await_args
        assert nkw["event_type"] == "analysis_failed"

    def test_notify_analysis_failed_swallows_errors_and_skips_missing_project(self):
        mgr = _build_manager()
        db = _build_db_with_scans(AsyncMock(), project=None)
        scan = {"_id": "scan-1", "project_id": "proj-1"}

        with (
            patch("app.core.worker.webhook_service.trigger_analysis_failed", new=AsyncMock()) as trigger,
            patch("app.core.worker.safe_notify_project_event", new=AsyncMock()) as notify,
        ):
            # Missing project -> no webhook/notification, no raise.
            asyncio.run(mgr._notify_analysis_failed(db, scan, "boom"))

        trigger.assert_not_awaited()
        notify.assert_not_awaited()
