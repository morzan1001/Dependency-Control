import asyncio

from app.core.constants import SCAN_STATUS_FAILED, SCAN_STATUS_PROCESSING
from app.services.analysis.engine import run_analysis
from tests.mocks.fake_mongo import FakeDatabase

_WORKER = "pod-a/worker-0"


def test_a_missing_scan_has_no_outcome_for_the_worker_to_retry():
    db = FakeDatabase()

    assert asyncio.run(run_analysis("missing-scan", [], db, worker_id=_WORKER)) is None
    assert asyncio.run(db.scans.count_documents({})) == 0


def _scan_of_a_deleted_project(worker_id: str) -> FakeDatabase:
    db = FakeDatabase()
    scan = {"_id": "scan-1", "project_id": "gone", "branch": "main", "status": SCAN_STATUS_PROCESSING}
    asyncio.run(db.scans.insert_one(scan | {"worker_id": worker_id}))
    return db


def test_a_scan_whose_project_is_gone_is_failed():
    db = _scan_of_a_deleted_project(_WORKER)

    assert asyncio.run(run_analysis("scan-1", [], db, worker_id=_WORKER)) == SCAN_STATUS_FAILED

    stored = asyncio.run(db.scans.find_one({"_id": "scan-1"}))
    assert (stored["status"], stored["error"]) == (SCAN_STATUS_FAILED, "Project not found")


def test_a_scan_whose_project_is_gone_is_left_to_the_worker_that_holds_its_claim():
    db = _scan_of_a_deleted_project("pod-b/worker-0")

    assert asyncio.run(run_analysis("scan-1", [], db, worker_id=_WORKER)) is None

    assert asyncio.run(db.scans.find_one({"_id": "scan-1"}))["status"] == SCAN_STATUS_PROCESSING
