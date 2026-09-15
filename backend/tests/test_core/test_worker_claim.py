"""The pending->processing claim is a compare-and-swap: it is all that keeps two pods off one scan."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase

_OTHER_POD_CLAIM = datetime(2025, 1, 1, tzinfo=timezone.utc)


async def _drain_one_job(db: FakeDatabase, scan_id: str) -> AsyncMock:
    manager = AnalysisWorkerManager(num_workers=1)
    manager.queue = asyncio.Queue()
    manager.queue.put_nowait(scan_id)

    run_analysis = AsyncMock(return_value=True)
    with (
        patch("app.core.worker.get_database", AsyncMock(return_value=db)),
        patch("app.core.worker.run_analysis", run_analysis),
    ):
        task = asyncio.create_task(manager.worker("worker-1"))
        try:
            await asyncio.wait_for(manager.queue.join(), timeout=5)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    return run_analysis


@pytest.mark.asyncio
async def test_a_scan_another_pod_is_already_processing_is_not_reclaimed():
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "proj-1", "active_analyzers": []})
    await db.scans.insert_one(
        {
            "_id": "scan-1",
            "project_id": "proj-1",
            "status": "processing",
            "worker_id": "pod-a/worker-1",
            "analysis_started_at": _OTHER_POD_CLAIM,
            "sbom_refs": [],
        }
    )

    claimed_at = (await db.scans.find_one({"_id": "scan-1"}))["analysis_started_at"]

    run_analysis = await _drain_one_job(db, "scan-1")

    run_analysis.assert_not_awaited()
    scan = await db.scans.find_one({"_id": "scan-1"})
    assert scan["worker_id"] == "pod-a/worker-1"
    assert scan["analysis_started_at"] == claimed_at


@pytest.mark.asyncio
async def test_a_pending_scan_is_claimed_and_flipped_to_processing():
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "proj-1", "active_analyzers": []})
    await db.scans.insert_one({"_id": "scan-1", "project_id": "proj-1", "status": "pending", "sbom_refs": []})

    run_analysis = await _drain_one_job(db, "scan-1")

    run_analysis.assert_awaited_once()
    scan = await db.scans.find_one({"_id": "scan-1"})
    assert scan["status"] == "processing"
    assert scan["worker_id"].endswith("/worker-1")
