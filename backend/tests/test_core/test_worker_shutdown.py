"""Graceful shutdown lets a running scan finish within the grace period and no longer."""

import asyncio
import logging
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase


@pytest_asyncio.fixture
async def running_scan():
    """A manager whose only worker sits inside run_analysis for scan-1 until the yielded event is set."""
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "proj-1", "active_analyzers": []})
    await db.scans.insert_one({"_id": "scan-1", "project_id": "proj-1", "status": "pending", "sbom_refs": []})
    started, release = asyncio.Event(), asyncio.Event()

    async def run_analysis(**_kwargs):
        started.set()
        await release.wait()
        return True

    with (
        patch("app.core.worker.get_database", AsyncMock(return_value=db)),
        patch("app.core.worker.run_analysis", run_analysis),
        patch("app.core.worker._release_memory_to_os"),
    ):
        manager = AnalysisWorkerManager(num_workers=1)
        manager.queue = asyncio.Queue()
        manager.queue.put_nowait("scan-1")
        manager.workers.append(asyncio.create_task(manager.worker("worker-1")))
        await asyncio.wait_for(started.wait(), timeout=5)
        yield manager, release


@pytest.mark.asyncio
async def test_stop_returns_as_soon_as_the_running_scan_finishes(running_scan):
    manager, release = running_scan

    stopping = asyncio.create_task(manager.stop())
    await asyncio.sleep(0.05)
    assert not stopping.done()

    loop = asyncio.get_running_loop()
    released_at = loop.time()
    release.set()
    await asyncio.wait_for(stopping, timeout=5)

    assert loop.time() - released_at < 0.2
    assert all(task.done() for task in manager.workers)


@pytest.mark.asyncio
async def test_stop_gives_up_on_a_scan_that_outlives_the_grace_period(running_scan, caplog):
    manager, _release = running_scan

    with patch("app.core.worker.DEFAULT_SHUTDOWN_TIMEOUT_SECONDS", 0.1), caplog.at_level(logging.WARNING):
        await asyncio.wait_for(manager.stop(), timeout=5)

    assert all(task.done() for task in manager.workers)
    assert any("Shutdown timeout" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_a_scan_whose_project_is_gone_does_not_hold_up_shutdown():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "scan-1", "project_id": "gone", "status": "pending", "sbom_refs": []})
    manager = AnalysisWorkerManager(num_workers=1)
    manager.queue = asyncio.Queue()
    manager.queue.put_nowait("scan-1")

    with (
        patch("app.core.worker.get_database", AsyncMock(return_value=db)),
        patch("app.core.worker.run_analysis", AsyncMock()) as run_analysis,
    ):
        manager.workers.append(asyncio.create_task(manager.worker("worker-1")))
        await asyncio.wait_for(manager.queue.join(), timeout=5)
        await asyncio.wait_for(manager.stop(), timeout=1)

    run_analysis.assert_not_awaited()
    scan = await db.scans.find_one({"_id": "scan-1"})
    assert (scan["status"], scan["error"]) == ("failed", "Project not found")


@pytest.mark.asyncio
async def test_stop_returns_once_the_cancelled_housekeeping_cleaned_up():
    cleaned_up = asyncio.Event()

    async def housekeeping():
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0.05)
            cleaned_up.set()

    manager = AnalysisWorkerManager(num_workers=1)
    manager.housekeeping_task = asyncio.create_task(housekeeping())
    await asyncio.sleep(0)
    await asyncio.wait_for(manager.stop(), timeout=5)

    assert cleaned_up.is_set()
