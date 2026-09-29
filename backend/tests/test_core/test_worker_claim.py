"""The pending->processing claim is a compare-and-swap: it is all that keeps two pods off one scan."""

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from prometheus_client import REGISTRY

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED
from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase

_OTHER_POD_CLAIM = datetime(2025, 1, 1, tzinfo=timezone.utc)


async def _drain_one_job(db: FakeDatabase, scan_id: str, run_analysis: Any = None) -> AsyncMock:
    manager = AnalysisWorkerManager(num_workers=1)
    manager.queue = asyncio.Queue()
    manager.queue.put_nowait(scan_id)

    run_analysis = run_analysis or AsyncMock(return_value=SCAN_STATUS_COMPLETED)
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


@pytest.mark.asyncio
async def test_the_analysis_is_told_which_sbom_generation_it_claimed():
    """The engine compares it at finalize, so an SBOM replaced mid-run is re-analysed rather than lost."""
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "proj-1", "active_analyzers": []})
    await db.scans.insert_one(
        {"_id": "scan-1", "project_id": "proj-1", "status": "pending", "sbom_refs": [], "sbom_generation": 3}
    )

    run_analysis = await _drain_one_job(db, "scan-1")

    assert run_analysis.await_args.kwargs["sbom_generation"] == 3


async def _pending_scan(db: FakeDatabase) -> None:
    await db.projects.insert_one({"_id": "proj-1", "active_analyzers": []})
    await db.scans.insert_one({"_id": "scan-1", "project_id": "proj-1", "status": "pending", "sbom_refs": []})


def _jobs(status: str) -> float:
    return REGISTRY.get_sample_value("worker_jobs_processed_total", {"status": status}) or 0.0


@pytest.mark.asyncio
async def test_the_analysis_is_told_which_worker_holds_the_claim():
    db = FakeDatabase()
    await _pending_scan(db)

    run_analysis = await _drain_one_job(db, "scan-1")

    assert run_analysis.await_args.kwargs["worker_id"] == (await db.scans.find_one({"_id": "scan-1"}))["worker_id"]


@pytest.mark.asyncio
async def test_a_scan_the_engine_failed_counts_as_a_failed_job():
    db = FakeDatabase()
    await _pending_scan(db)
    failed_before, success_before = _jobs("failed"), _jobs("success")

    await _drain_one_job(db, "scan-1", AsyncMock(return_value=SCAN_STATUS_FAILED))

    assert (_jobs("failed") - failed_before, _jobs("success") - success_before) == (1, 0)


@pytest.mark.asyncio
async def test_an_error_after_the_scan_left_this_worker_neither_fails_nor_announces_it():
    db = FakeDatabase()
    await _pending_scan(db)
    failed_before = _jobs("failed")

    async def _finalize_then_raise(**_kwargs):
        await db.scans.update_one({"_id": "scan-1"}, {"$set": {"status": SCAN_STATUS_COMPLETED}})
        raise RuntimeError("primary stepped down")

    with patch("app.core.worker.notify_analysis_failed", AsyncMock()) as notify:
        await _drain_one_job(db, "scan-1", _finalize_then_raise)

    assert (await db.scans.find_one({"_id": "scan-1"}))["status"] == SCAN_STATUS_COMPLETED
    notify.assert_not_awaited()
    assert _jobs("failed") == failed_before


@pytest.mark.asyncio
async def test_a_long_analysis_keeps_renewing_its_claim():
    db = FakeDatabase()
    await _pending_scan(db)
    leases: list[datetime] = []

    async def _slow_analysis(**_kwargs):
        leases.append((await db.scans.find_one({"_id": "scan-1"}))["analysis_started_at"])
        await asyncio.sleep(0.05)
        leases.append((await db.scans.find_one({"_id": "scan-1"}))["analysis_started_at"])
        return SCAN_STATUS_COMPLETED

    with patch("app.core.worker._CLAIM_RENEW_SECONDS", 0.01):
        await _drain_one_job(db, "scan-1", _slow_analysis)

    assert leases[1] > leases[0]
