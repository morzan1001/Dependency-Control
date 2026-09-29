"""Scan status transitions: each one is a conditional write, so a writer holding a stale view of the
scan changes nothing instead of overwriting the run that replaced it."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED, SCAN_STATUS_PENDING, SCAN_STATUS_PROCESSING
from app.core.housekeeping import recover_stuck_scans
from app.core.worker import AnalysisWorkerManager
from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase

_SCAN = "s1"
_WORKER_A = "pod-a/worker-0"
_WORKER_B = "pod-b/worker-0"


async def _seeded(**fields) -> FakeDatabase:
    db = FakeDatabase()
    await db.scans.insert_one({"_id": _SCAN, "project_id": "p1", "branch": "main", **fields})
    return db


async def _stored(db: FakeDatabase) -> dict:
    return await db.scans.find_one({"_id": _SCAN})


@pytest.mark.asyncio
async def test_a_pending_scan_goes_to_exactly_one_worker():
    db = await _seeded(status=SCAN_STATUS_PENDING)
    repo = ScanRepository(db)

    first = await repo.claim_pending(_SCAN, _WORKER_A)
    second = await repo.claim_pending(_SCAN, _WORKER_B)

    assert first["status"] == SCAN_STATUS_PROCESSING
    assert first["worker_id"] == _WORKER_A
    assert second is None


@pytest.mark.asyncio
async def test_a_worker_cannot_fail_a_run_another_worker_has_since_claimed():
    """Housekeeping reset A's slow run and B claimed it; A's late exception must not fail B's run."""
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_B)

    failed = await ScanRepository(db).mark_failed(_SCAN, "boom", worker_id=_WORKER_A)

    assert failed is False
    assert (await _stored(db))["status"] == SCAN_STATUS_PROCESSING


@pytest.mark.asyncio
async def test_a_failure_records_its_reason():
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A)

    failed = await ScanRepository(db).mark_failed(_SCAN, "boom", worker_id=_WORKER_A)

    stored = await _stored(db)
    assert failed is True
    assert (stored["status"], stored["error"]) == (SCAN_STATUS_FAILED, "boom")


@pytest.mark.asyncio
async def test_a_completed_scan_is_not_failed_afterwards():
    db = await _seeded(status=SCAN_STATUS_COMPLETED, worker_id=_WORKER_A)

    assert await ScanRepository(db).mark_failed(_SCAN, "boom", worker_id=_WORKER_A) is False
    assert (await _stored(db))["status"] == SCAN_STATUS_COMPLETED


@pytest.mark.asyncio
async def test_a_requeue_releases_the_worker_and_counts_the_attempt():
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A, retry_count=1)

    assert await ScanRepository(db).requeue(_SCAN) is True

    stored = await _stored(db)
    assert (stored["status"], stored["worker_id"], stored["retry_count"]) == (SCAN_STATUS_PENDING, None, 2)


@pytest.mark.asyncio
async def test_a_requeue_leaves_a_finished_scan_alone():
    db = await _seeded(status=SCAN_STATUS_COMPLETED)

    assert await ScanRepository(db).requeue(_SCAN) is False
    assert (await _stored(db))["status"] == SCAN_STATUS_COMPLETED


@pytest.mark.asyncio
async def test_new_input_reopens_only_a_finished_scan():
    finished = await _seeded(status=SCAN_STATUS_COMPLETED, retry_count=3)
    running = await _seeded(status=SCAN_STATUS_PROCESSING, retry_count=3)

    assert await ScanRepository(finished).reopen_finished(_SCAN) is True
    assert await ScanRepository(running).reopen_finished(_SCAN) is False
    assert ((await _stored(finished))["status"], (await _stored(finished))["retry_count"]) == (SCAN_STATUS_PENDING, 0)
    assert (await _stored(running))["status"] == SCAN_STATUS_PROCESSING


def test_the_retry_ceiling_does_not_fail_or_announce_a_scan_another_worker_holds():
    """The engine requeued the scan to pending; once another worker has claimed it, it is not ours."""
    db = asyncio.run(_seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_B))
    manager = AnalysisWorkerManager(num_workers=1)
    manager.queue = asyncio.Queue()

    with patch.object(manager, "_notify_analysis_failed", AsyncMock()) as notify:
        asyncio.run(manager._handle_failed_analysis({"_id": _SCAN, "retry_count": 4}, _SCAN, db))

    notify.assert_not_awaited()
    assert asyncio.run(_stored(db))["status"] == SCAN_STATUS_PROCESSING


@pytest.mark.asyncio
async def test_stuck_scan_recovery_requeues_and_releases_the_worker():
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A, analysis_started_at=None, retry_count=0)
    worker = AsyncMock()

    with patch("app.core.housekeeping.get_database", AsyncMock(return_value=db)):
        await recover_stuck_scans(worker)

    stored = await _stored(db)
    assert (stored["status"], stored["worker_id"], stored["retry_count"]) == (SCAN_STATUS_PENDING, None, 1)
    worker.add_job.assert_awaited_once_with(_SCAN)
