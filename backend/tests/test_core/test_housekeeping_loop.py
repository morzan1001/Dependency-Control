import asyncio
import logging
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from prometheus_client import REGISTRY

from app.core import housekeeping
from app.core.config import settings
from app.core.constants import HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC as QUIET_HOUR
from app.core.metrics import update_archive_stats
from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase

_WORKER_JOBS = {
    "recover_stuck_scans": "Stuck scan recovery",
    "check_scheduled_rescans": "Scheduled re-scan check",
    "trigger_stale_pending_scans": "Stale scan loop: trigger_stale_pending_scans",
    "requeue_waiting_adhoc_jobs": "Stale scan loop: requeue_waiting_adhoc_jobs",
}
_STATS_JOBS = {
    "update_db_stats": "Database statistics",
    "update_archive_stats": "Archive statistics",
    "update_cache_stats": "Cache statistics",
}
_DATABASE_JOBS = {
    "run_waiver_recalc": "Waiver recalculation",
    "run_housekeeping": "Housekeeping task",
    "_run_retention": "Housekeeping: retention",
    "sync_branch_status": "Branch status sync",
    "run_update_frequency_reconcile": "Update-frequency reconcile",
}
_LABELS = {**_WORKER_JOBS, **_STATS_JOBS, **_DATABASE_JOBS}
_PASSES = 2


class _StopLoop(Exception):
    """Ends a loop after its passes."""


def _patch_jobs(monkeypatch: pytest.MonkeyPatch, job: Any) -> FakeDatabase:
    db = FakeDatabase()

    async def _get_database() -> FakeDatabase:
        return db

    for name in _LABELS:
        named_job = job(name)
        # The stale scan loop labels a job by its function name.
        named_job.__name__ = name
        monkeypatch.setattr(housekeeping, name, named_job)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
    monkeypatch.setattr(housekeeping, "_reconcile_due", lambda _now, _last_run: True)
    monkeypatch.setattr(settings, "UPDATE_FREQUENCY_RECONCILE_ENABLED", True)
    return db


def _noop_jobs(monkeypatch: pytest.MonkeyPatch, db: FakeDatabase) -> None:
    async def _noop(*_args: Any) -> None:
        return None

    async def _get_database() -> FakeDatabase:
        return db

    for name in _LABELS:
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)


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

    expected = (
        [(name, (manager,)) for name in _WORKER_JOBS]
        + [("update_db_stats", (db,)), ("update_archive_stats", (db, None)), ("update_cache_stats", ())]
        + [(name, (db,)) for name in _DATABASE_JOBS]
    )
    assert sorted(ran, key=lambda call: call[0]) == sorted(expected * _PASSES, key=lambda call: call[0])
    assert [(record.getMessage(), record.exc_info is not None) for record in caplog.records] == [
        (f"{_LABELS[failing]} failed: mongo unreachable", True)
    ] * _PASSES


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


@pytest.mark.asyncio
async def test_each_pass_hands_the_archive_count_its_bytes_were_summed_at_to_the_next_and_a_failure_none(monkeypatch):
    handed: list[int | None] = []
    passes = iter(range(4))

    async def _update_archive_stats(_db: Any, summed_at: int | None) -> int:
        handed.append(summed_at)
        if len(handed) == 3:
            raise RuntimeError("mongo unreachable")
        return len(handed) * 10

    async def _sleep(_seconds: float) -> None:
        if next(passes) == 3:
            raise _StopLoop

    _noop_jobs(monkeypatch, FakeDatabase())
    monkeypatch.setattr(housekeeping, "update_archive_stats", _update_archive_stats)
    monkeypatch.setattr(housekeeping, "_reconcile_due", lambda _now, _last_run: False)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))

    with pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop(AnalysisWorkerManager(num_workers=1))

    assert handed == [None, 10, 20, None]


@pytest.mark.asyncio
async def test_an_insert_and_a_delete_that_cancel_out_stay_unsummed_until_the_daily_pass_resums(monkeypatch):
    db = FakeDatabase()
    await db.archive_metadata.insert_one({"_id": "a1", "compressed_size_bytes": 100})
    await db.archive_metadata.insert_one({"_id": "a2", "compressed_size_bytes": 50})
    loud_hour = (QUIET_HOUR + 12) % 24
    clock = iter(
        datetime(2026, 6, day, hour, tzinfo=timezone.utc)
        for day, hour in ((1, loud_hour), (1, loud_hour), (2, QUIET_HOUR), (2, loud_hour))
    )
    reported: list[float | None] = []

    async def _sleep(_seconds: float) -> None:
        reported.append(REGISTRY.get_sample_value("archive_stored_bytes_total"))
        if len(reported) == 1:
            await db.archive_metadata.delete_one({"_id": "a2"})
            await db.archive_metadata.insert_one({"_id": "a3", "compressed_size_bytes": 70})
        if len(reported) == 4:
            raise _StopLoop

    _noop_jobs(monkeypatch, db)
    monkeypatch.setattr(housekeeping, "update_archive_stats", update_archive_stats)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))
    monkeypatch.setattr(
        housekeeping,
        "datetime",
        SimpleNamespace(min=datetime.min.replace(tzinfo=timezone.utc), now=lambda _tz=None: next(clock)),
    )

    with pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop(AnalysisWorkerManager(num_workers=1))

    assert reported == [150, 150, 150, 170]
