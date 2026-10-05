"""Every finished job releases its garbage, whatever way the analysis ended."""

import gc
import weakref
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED, SCAN_STATUS_PENDING
from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase


class _Payload:
    pass


def _leave_cyclic_garbage(refs: list[weakref.ref]) -> None:
    held = _Payload()
    held.self_ref = held
    refs.append(weakref.ref(held))


@pytest.fixture
def automatic_gc_off():
    was_enabled = gc.isenabled()
    gc.disable()
    yield
    if was_enabled:
        gc.enable()


async def _scan_db() -> FakeDatabase:
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "proj-1", "active_analyzers": []})
    await db.scans.insert_one({"_id": "scan-1", "project_id": "proj-1", "status": SCAN_STATUS_PENDING})
    return db


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["completed", "failed", "raised"])
async def test_a_scan_job_releases_what_its_analysis_left_behind(automatic_gc_off, ending):
    db = await _scan_db()
    refs: list[weakref.ref] = []

    async def _analysis(**_kwargs):
        _leave_cyclic_garbage(refs)
        if ending == "raised":
            raise RuntimeError("grype crashed")
        return SCAN_STATUS_COMPLETED if ending == "completed" else SCAN_STATUS_FAILED

    with (
        patch("app.core.worker.get_database", AsyncMock(return_value=db)),
        patch("app.core.worker.run_analysis", _analysis),
        patch("app.core.worker.notify_analysis_failed", AsyncMock()),
    ):
        await AnalysisWorkerManager(num_workers=1)._process("scan-1", "pod/worker-1")

    assert refs and refs[0]() is None


@pytest.mark.asyncio
async def test_an_adhoc_job_releases_what_its_analysis_left_behind(automatic_gc_off):
    db = FakeDatabase()
    await db.adhoc_jobs.insert_one({"_id": "job-1", "status": SCAN_STATUS_PENDING})
    refs: list[weakref.ref] = []

    async def _adhoc(_db, _job):
        _leave_cyclic_garbage(refs)
        return {"status": SCAN_STATUS_COMPLETED, "result_file_id": "f-1"}

    with (
        patch("app.core.worker.get_database", AsyncMock(return_value=db)),
        patch("app.core.worker._run_adhoc_job", _adhoc),
    ):
        await AnalysisWorkerManager(num_workers=1)._process_adhoc("job-1", "pod/worker-1")

    assert (await db.adhoc_jobs.find_one({"_id": "job-1"}))["status"] == SCAN_STATUS_COMPLETED
    assert refs and refs[0]() is None
