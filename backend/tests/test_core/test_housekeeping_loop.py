import asyncio
import logging
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import housekeeping
from app.core.config import settings
from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase

_WORKER_JOBS = {
    "recover_stuck_scans": "Stuck scan recovery",
    "check_scheduled_rescans": "Scheduled re-scan check",
    "trigger_stale_pending_scans": "Stale scan loop: trigger_stale_pending_scans",
    "requeue_waiting_adhoc_jobs": "Stale scan loop: requeue_waiting_adhoc_jobs",
}
_DATABASE_JOBS = {
    "run_waiver_recalc": "Waiver recalculation",
    "run_housekeeping": "Housekeeping task",
    "_run_retention": "Housekeeping: retention",
    "sync_branch_status": "Branch status sync",
    "run_update_frequency_reconcile": "Update-frequency reconcile",
}
_LABELS = {**_WORKER_JOBS, **_DATABASE_JOBS}
_QUIET_TASKS = ("update_db_stats", "update_archive_stats", "update_cache_stats")
_PASSES = 2


class _StopLoop(Exception):
    """Ends a loop after its passes."""


def _patch_jobs(monkeypatch: pytest.MonkeyPatch, job: Any) -> FakeDatabase:
    db = FakeDatabase()

    async def _get_database() -> FakeDatabase:
        return db

    async def _noop(*_args: Any) -> None:
        return None

    for name in _LABELS:
        named_job = job(name)
        # The stale scan loop labels a job by its function name.
        named_job.__name__ = name
        monkeypatch.setattr(housekeeping, name, named_job)
    for name in _QUIET_TASKS:
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
    monkeypatch.setattr(housekeeping, "_reconcile_due", lambda _now, _last_run: True)
    monkeypatch.setattr(settings, "UPDATE_FREQUENCY_RECONCILE_ENABLED", True)
    return db


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", list(_LABELS))
async def test_every_job_runs_each_pass_and_a_failure_is_logged_by_its_label(monkeypatch, caplog, failing):
    ran: list[tuple[str, tuple[Any, ...]]] = []

    def _job(name: str):
        async def _run(*args: Any) -> None:
            ran.append((name, args))
            if name == failing:
                raise RuntimeError("mongo unreachable")

        return _run

    db = _patch_jobs(monkeypatch, _job)
    sleeps = 0

    async def _sleep(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps % _PASSES == 0:
            raise _StopLoop

    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))
    manager = AnalysisWorkerManager(num_workers=1)

    with caplog.at_level(logging.ERROR, logger="app.core.housekeeping"):
        for loop in housekeeping.background_loops(manager):
            with pytest.raises(_StopLoop):
                await loop

    expected = [(name, (manager,)) for name in _WORKER_JOBS] + [(name, (db,)) for name in _DATABASE_JOBS]
    assert sorted(ran, key=lambda call: call[0]) == sorted(expected * _PASSES, key=lambda call: call[0])
    assert [record.getMessage() for record in caplog.records] == [f"{_LABELS[failing]} failed: mongo unreachable"] * 2


@pytest.mark.asyncio
@pytest.mark.parametrize("long_job", ["run_housekeeping", "_run_retention", "sync_branch_status", "run_waiver_recalc"])
async def test_a_job_outlasting_the_interval_keeps_recovery_and_the_reconcile_on_their_rhythm(monkeypatch, long_job):
    ran: list[str] = []

    def _job(name: str):
        async def _run(*_args: Any) -> None:
            ran.append(name)
            if name == long_job:
                await asyncio.Event().wait()

        return _run

    _patch_jobs(monkeypatch, _job)
    monkeypatch.setattr(housekeeping, "HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS", 0.01)
    manager = AnalysisWorkerManager(num_workers=1)

    await manager.start()
    await asyncio.sleep(0.2)
    await manager.stop()

    assert ran.count("recover_stuck_scans") > 1
    assert ran.count("run_update_frequency_reconcile") > 1
