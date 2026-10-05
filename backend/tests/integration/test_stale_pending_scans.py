"""Which pending scans the stale loop queues. Every pod runs it every few seconds, so it is also what
picks up a scan whose queue entry died with its pod; a scan it never picks up blocks its lineage."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import (
    HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
)
from app.core.housekeeping import trigger_stale_pending_scans
from app.core.worker import AnalysisWorkerManager
from app.models.project import Project, Scan
from app.services.rescan import create_rescan

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_STALE = timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS + 60)
_FRESH = timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS / 2)
_PROJECT = Project(id="p1", name="p1")
_SCANNER = ["trufflehog"]


def _scan(scan_id: str, created_ago: timedelta, *, status: str = SCAN_STATUS_PENDING, **fields) -> dict:
    created_at = datetime.now(timezone.utc) - created_ago
    scan = Scan(id=scan_id, project_id=_PROJECT.id, branch="main", status=status, created_at=created_at, **fields)
    return scan.model_dump(by_alias=True)


def _housekeeping_on(db, monkeypatch) -> None:
    async def _get_database():
        return db

    monkeypatch.setattr("app.core.housekeeping.get_database", _get_database)


def _queued(manager: AnalysisWorkerManager) -> list[str]:
    return [manager.queue.get_nowait() for _ in range(manager.queue.qsize())]


async def test_a_rescan_whose_queue_entry_died_with_its_pod_is_claimed_by_another(db, running_worker, monkeypatch):
    await db.projects.insert_one(_PROJECT.model_dump(by_alias=True))
    source = {"_id": "build", "project_id": _PROJECT.id, "branch": "main", "sbom_refs": []}
    rescan = await create_rescan(db, source, AnalysisWorkerManager(num_workers=1))
    assert rescan is not None
    await db.scans.update_one({"_id": rescan.id}, {"$set": {"created_at": datetime.now(timezone.utc) - _STALE}})
    claimed: list[str] = []

    async def _analysis(scan_id, **_kwargs):
        claimed.append(scan_id)
        return SCAN_STATUS_COMPLETED

    monkeypatch.setattr("app.core.worker.run_analysis", _analysis)
    _housekeeping_on(db, monkeypatch)

    await trigger_stale_pending_scans(running_worker)
    await running_worker.queue.join()

    assert claimed == [rescan.id]


async def test_each_pass_queues_only_the_oldest_scans_the_workers_can_take(db, monkeypatch):
    now = datetime.now(timezone.utc)
    await db.scans.insert_many(
        [
            _scan("newest", _STALE),
            _scan("oldest", 3 * _STALE, last_result_at=now - _STALE, received_results=_SCANNER),
            _scan("middle", 2 * _STALE),
        ]
    )
    manager = AnalysisWorkerManager(num_workers=2)
    _housekeeping_on(db, monkeypatch)

    await trigger_stale_pending_scans(manager)

    assert _queued(manager) == ["oldest", "middle"]


async def test_a_pod_whose_workers_all_have_a_job_waiting_queues_nothing(db, monkeypatch):
    now = datetime.now(timezone.utc)
    await db.scans.insert_one(_scan("stale", 2 * _STALE, last_result_at=now - _STALE, received_results=_SCANNER))
    manager = AnalysisWorkerManager(num_workers=1)
    await manager.add_job("waiting")
    _housekeeping_on(db, monkeypatch)

    await trigger_stale_pending_scans(manager)

    assert _queued(manager) == ["waiting"]


async def test_a_scan_still_registering_or_receiving_results_or_not_pending_is_left_alone(db, monkeypatch):
    now = datetime.now(timezone.utc)
    await db.scans.insert_many(
        [
            # The ingest upsert's shape before its scanner result is registered.
            {"_id": "registering", "project_id": _PROJECT.id, "status": SCAN_STATUS_PENDING, "created_at": now},
            _scan("receiving", 2 * _STALE, last_result_at=now - _FRESH, received_results=_SCANNER),
            _scan("done", 2 * _STALE, status=SCAN_STATUS_COMPLETED),
            _scan("running", 2 * _STALE, status=SCAN_STATUS_PROCESSING, last_result_at=now - _STALE),
        ]
    )
    manager = AnalysisWorkerManager(num_workers=4)
    _housekeeping_on(db, monkeypatch)

    await trigger_stale_pending_scans(manager)

    assert _queued(manager) == []
