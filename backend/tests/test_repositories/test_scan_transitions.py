"""Scan status transitions: each one is a conditional write, so a writer holding a stale view of the
scan changes nothing instead of overwriting the run that replaced it."""

import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import (
    HOUSEKEEPING_MAX_SCAN_RETRIES,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    SCAN_USABLE_STATUSES,
)
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
    assert stored["completed_at"] is not None


@pytest.mark.asyncio
async def test_a_failed_rescan_reports_its_run_on_the_build_it_re_analyses():
    """Otherwise the build keeps announcing the rescan as pending forever."""
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A, is_rescan=True, original_scan_id="root")
    await db.scans.insert_one({"_id": "root", "latest_run": {"scan_id": _SCAN, "status": SCAN_STATUS_PENDING}})

    await ScanRepository(db).mark_failed(_SCAN, "boom", worker_id=_WORKER_A)

    run = (await db.scans.find_one({"_id": "root"}))["latest_run"]
    assert run == {"scan_id": _SCAN, "status": SCAN_STATUS_FAILED, "completed_at": (await _stored(db))["completed_at"]}


@pytest.mark.asyncio
async def test_a_failed_rescan_leaves_a_build_re_ingested_since_alone():
    db = await _seeded(
        status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A, is_rescan=True, original_scan_id="root", sbom_generation=1
    )
    own_run = {"scan_id": "root", "status": SCAN_STATUS_COMPLETED}
    await db.scans.insert_one({"_id": "root", "sbom_generation": 2, "latest_run": own_run})

    await ScanRepository(db).mark_failed(_SCAN, "boom", worker_id=_WORKER_A)

    assert (await db.scans.find_one({"_id": "root"}))["latest_run"] == own_run


@pytest.mark.asyncio
async def test_a_completed_scan_is_not_failed_afterwards():
    db = await _seeded(status=SCAN_STATUS_COMPLETED, worker_id=_WORKER_A)

    assert await ScanRepository(db).mark_failed(_SCAN, "boom", worker_id=_WORKER_A) is False
    assert (await _stored(db))["status"] == SCAN_STATUS_COMPLETED


@pytest.mark.asyncio
async def test_a_requeue_releases_the_worker_and_counts_the_attempt():
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A, retry_count=1)

    assert await ScanRepository(db).requeue(_SCAN, _WORKER_A, counter="retry_count") is True

    stored = await _stored(db)
    assert (stored["status"], stored["worker_id"], stored["retry_count"]) == (SCAN_STATUS_PENDING, None, 2)


@pytest.mark.asyncio
async def test_a_requeue_leaves_a_finished_scan_alone():
    db = await _seeded(status=SCAN_STATUS_COMPLETED, worker_id=_WORKER_A)

    assert await ScanRepository(db).requeue(_SCAN, _WORKER_A, counter="retry_count") is False
    assert (await _stored(db))["status"] == SCAN_STATUS_COMPLETED


@pytest.mark.asyncio
async def test_a_writer_that_lost_the_claim_cannot_requeue_the_run_that_replaced_it():
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_B, retry_count=1)

    assert await ScanRepository(db).requeue(_SCAN, _WORKER_A, counter="retry_count") is False
    stored = await _stored(db)
    assert (stored["status"], stored["worker_id"], stored["retry_count"]) == (SCAN_STATUS_PROCESSING, _WORKER_B, 1)


@pytest.mark.asyncio
async def test_renewing_a_claim_moves_its_lease_only_for_the_holder():
    stale = datetime(2025, 1, 1, tzinfo=timezone.utc)
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A, analysis_started_at=stale)
    repo = ScanRepository(db)

    assert await repo.renew_claim(_SCAN, _WORKER_B) is False
    assert (await _stored(db))["analysis_started_at"] == stale

    assert await repo.renew_claim(_SCAN, _WORKER_A) is True
    assert (await _stored(db))["analysis_started_at"] > stale


@pytest.mark.asyncio
async def test_new_input_reopens_only_a_finished_scan():
    finished = await _seeded(status=SCAN_STATUS_COMPLETED, retry_count=3, stuck_retry_count=2)
    running = await _seeded(status=SCAN_STATUS_PROCESSING, retry_count=3)

    assert await ScanRepository(finished).reopen_finished(_SCAN) is True
    assert await ScanRepository(running).reopen_finished(_SCAN) is False
    reopened = await _stored(finished)
    assert (reopened["status"], reopened["retry_count"], reopened["stuck_retry_count"]) == (SCAN_STATUS_PENDING, 0, 0)
    assert (await _stored(running))["status"] == SCAN_STATUS_PROCESSING


@pytest.mark.asyncio
async def test_a_failed_scan_reopens_only_for_a_caller_that_allows_it():
    failed = await _seeded(status=SCAN_STATUS_FAILED, retry_count=5, stuck_retry_count=3)

    assert await ScanRepository(failed).reopen_finished(_SCAN) is False
    assert (await _stored(failed))["status"] == SCAN_STATUS_FAILED
    assert await ScanRepository(failed).reopen_finished(_SCAN, statuses=[*SCAN_USABLE_STATUSES, SCAN_STATUS_FAILED])
    reopened = await _stored(failed)
    assert (reopened["status"], reopened["retry_count"], reopened["stuck_retry_count"]) == (SCAN_STATUS_PENDING, 0, 0)


def test_the_retry_ceiling_does_not_fail_or_announce_a_scan_another_worker_holds():
    """The engine requeued the scan to pending; once another worker has claimed it, it is not ours."""
    db = asyncio.run(_seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_B))
    manager = AnalysisWorkerManager(num_workers=1)
    manager.queue = asyncio.Queue()

    with patch("app.core.worker.notify_analysis_failed", AsyncMock()) as notify:
        asyncio.run(manager._handle_rescheduled({"_id": _SCAN, "retry_count": 4}, db, time.time()))

    notify.assert_not_called()
    assert asyncio.run(_stored(db))["status"] == SCAN_STATUS_PROCESSING


@pytest.mark.asyncio
async def test_stuck_scan_recovery_requeues_and_releases_the_worker():
    db = await _seeded(status=SCAN_STATUS_PROCESSING, worker_id=_WORKER_A, analysis_started_at=None, retry_count=0)
    worker = AsyncMock()

    with patch("app.core.housekeeping.get_database", AsyncMock(return_value=db)):
        await recover_stuck_scans(worker)

    stored = await _stored(db)
    assert (stored["status"], stored["worker_id"], stored["stuck_retry_count"]) == (SCAN_STATUS_PENDING, None, 1)
    worker.add_job.assert_awaited_once_with(_SCAN)


@pytest.mark.asyncio
async def test_rescheduling_for_new_input_does_not_use_up_the_budget_for_stuck_runs():
    db = await _seeded(
        status=SCAN_STATUS_PROCESSING,
        worker_id=_WORKER_A,
        analysis_started_at=None,
        retry_count=HOUSEKEEPING_MAX_SCAN_RETRIES,
    )

    with patch("app.core.housekeeping.get_database", AsyncMock(return_value=db)):
        await recover_stuck_scans(AsyncMock())

    assert (await _stored(db))["status"] == SCAN_STATUS_PENDING


@pytest.mark.asyncio
async def test_giving_up_on_a_stuck_scan_announces_the_failure():
    db = await _seeded(
        status=SCAN_STATUS_PROCESSING,
        worker_id=_WORKER_A,
        analysis_started_at=None,
        stuck_retry_count=HOUSEKEEPING_MAX_SCAN_RETRIES,
    )

    with (
        patch("app.core.housekeeping.get_database", AsyncMock(return_value=db)),
        patch("app.core.housekeeping.notify_analysis_failed", AsyncMock()) as notify,
    ):
        await recover_stuck_scans(AsyncMock())
        await recover_stuck_scans(AsyncMock())

    assert (await _stored(db))["status"] == SCAN_STATUS_FAILED
    notify.assert_awaited_once_with(db, _SCAN, "p1", "Analysis timed out or worker crashed multiple times.")
