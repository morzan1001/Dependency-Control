"""Worker retry handling: the engine owns status/retry_count writes; the worker only enforces the ceiling."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from app.core import worker
from app.core.worker import AnalysisWorkerManager
from app.services.analysis.notifications import notify_analysis_failed
from tests.mocks.fake_mongo import FakeDatabase


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


def _db_with_requeued_scan() -> FakeDatabase:
    db = FakeDatabase()
    asyncio.run(db.scans.insert_one({"_id": "scan-1", "project_id": "proj-1", "status": "pending"}))
    return db


class TestHandleRescheduled:
    def test_under_limit_requeues_without_writing_retry_count(self):
        mgr = _build_manager()
        update_one = AsyncMock()
        db = _build_db_with_scans(update_one)
        scan = {"_id": "scan-1", "retry_count": 1}

        asyncio.run(mgr._handle_rescheduled(scan, db, time.time()))

        assert mgr.queue.qsize() == 1
        assert mgr.queue.get_nowait() == "scan-1"
        update_one.assert_not_awaited()

    def test_at_limit_marks_failed_and_does_not_requeue(self):
        mgr = _build_manager()
        db = _db_with_requeued_scan()
        # retry_count=4 in snapshot + 1 (engine inc) = 5, hits ceiling.
        scan = {"_id": "scan-1", "retry_count": 4}

        asyncio.run(mgr._handle_rescheduled(scan, db, time.time()))

        assert mgr.queue.qsize() == 0
        assert asyncio.run(db.scans.find_one({"_id": "scan-1"}))["status"] == "failed"

    def test_at_limit_announces_the_failure(self):
        mgr = _build_manager()
        db = _db_with_requeued_scan()
        scan = {"_id": "scan-1", "project_id": "proj-1", "retry_count": 4}

        with patch("app.core.worker.notify_analysis_failed", new=AsyncMock()) as notify:
            asyncio.run(mgr._handle_rescheduled(scan, db, time.time()))

        notify.assert_called_once()
        _, scan_id, project_id, error = notify.call_args.args
        assert (scan_id, project_id) == ("scan-1", "proj-1")
        assert "retry attempts" in error

    def test_the_worker_moves_on_while_the_failure_is_still_being_announced(self):
        """A blackholed webhook host holds its delivery for tens of seconds; the analysis slot must not wait."""
        mgr = _build_manager()
        db = _db_with_requeued_scan()
        scan = {"_id": "scan-1", "project_id": "proj-1", "retry_count": 4}
        delivered: list[str] = []

        async def _run() -> None:
            release = asyncio.Event()

            async def _slow_notice(_db, scan_id, _project_id, _error):
                await release.wait()
                delivered.append(scan_id)

            with patch("app.core.worker.notify_analysis_failed", _slow_notice):
                await asyncio.wait_for(mgr._handle_rescheduled(scan, db, time.time()), timeout=1)
                assert delivered == []
                release.set()
                await asyncio.gather(*worker._failure_notices)

        asyncio.run(_run())

        assert delivered == ["scan-1"]
        assert worker._failure_notices == set()


class TestNotifyAnalysisFailed:
    def test_sends_the_webhook_and_the_member_notification(self):
        db = _build_db_with_scans(AsyncMock(), project={"_id": "proj-1", "name": "My Project"})

        with (
            patch(
                "app.services.analysis.notifications.webhook_service.trigger_analysis_failed", AsyncMock()
            ) as trigger,
            patch("app.services.analysis.notifications.safe_notify_project_event", AsyncMock()) as notify,
        ):
            asyncio.run(notify_analysis_failed(db, "scan-1", "proj-1", "boom"))

        _, tkw = trigger.await_args
        assert (tkw["scan_id"], tkw["project_id"], tkw["project_name"], tkw["error_message"]) == (
            "scan-1",
            "proj-1",
            "My Project",
            "boom",
        )
        assert notify.await_args.kwargs["event_type"] == "analysis_failed"

    def test_swallows_errors_and_skips_a_missing_project(self):
        db = _build_db_with_scans(AsyncMock(), project=None)

        with (
            patch(
                "app.services.analysis.notifications.webhook_service.trigger_analysis_failed", AsyncMock()
            ) as trigger,
            patch("app.services.analysis.notifications.safe_notify_project_event", AsyncMock()) as notify,
        ):
            asyncio.run(notify_analysis_failed(db, "scan-1", "proj-1", "boom"))

        trigger.assert_not_awaited()
        notify.assert_not_awaited()

        db.projects.find_one = AsyncMock(side_effect=RuntimeError("primary stepped down"))
        asyncio.run(notify_analysis_failed(db, "scan-1", "proj-1", "boom"))

    def test_a_failed_webhook_lookup_still_notifies_the_members(self):
        db = FakeDatabase()
        asyncio.run(db.projects.insert_one({"_id": "proj-1", "name": "My Project"}))
        db.webhooks.find = MagicMock(side_effect=RuntimeError("primary stepped down"))

        with patch("app.services.analysis.notifications.safe_notify_project_event", AsyncMock()) as notify:
            asyncio.run(notify_analysis_failed(db, "scan-1", "proj-1", "boom"))

        assert notify.await_args.kwargs["event_type"] == "analysis_failed"
