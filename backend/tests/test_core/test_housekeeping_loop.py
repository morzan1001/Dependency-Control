import logging
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from prometheus_client import REGISTRY

from app.core import housekeeping
from app.core.constants import HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC as QUIET_HOUR
from app.core.metrics import update_archive_stats
from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase

_LABELS = {
    "recover_stuck_scans": "Stuck scan recovery",
    "check_scheduled_rescans": "Scheduled re-scan check",
    "update_db_stats": "Database statistics",
    "update_archive_stats": "Archive statistics",
    "update_cache_stats": "Cache statistics",
    "run_housekeeping": "Housekeeping task",
    "sync_branch_status": "Branch status sync",
}
_QUIET_TASKS = (
    "run_waiver_recalc",
    "_run_retention",
    "reconcile_update_frequency_ledger",
)


class _StopLoop(Exception):
    """Breaks out of the endless housekeeping loop."""


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", list(_LABELS))
async def test_a_failing_task_is_logged_by_label_and_the_loop_runs_the_others(monkeypatch, caplog, failing):
    ran: list[str] = []

    def _task(name: str):
        async def _run(*_args: Any) -> None:
            ran.append(name)
            if name == failing:
                raise RuntimeError("mongo unreachable")

        return _run

    async def _noop(*_args: Any) -> None:
        return None

    async def _get_database() -> FakeDatabase:
        return FakeDatabase()

    async def _sleep(_seconds: float) -> None:
        raise _StopLoop

    for name in _LABELS:
        monkeypatch.setattr(housekeeping, name, _task(name))
    for name in _QUIET_TASKS:
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))

    with caplog.at_level(logging.ERROR, logger="app.core.housekeeping"), pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop(AnalysisWorkerManager(num_workers=1))

    assert ran == list(_LABELS)
    assert [(record.getMessage(), record.exc_info is not None) for record in caplog.records] == [
        (f"{_LABELS[failing]} failed: mongo unreachable", True)
    ]


@pytest.mark.asyncio
async def test_each_pass_hands_the_archive_count_its_bytes_were_summed_at_to_the_next_and_a_failure_none(monkeypatch):
    handed: list[int | None] = []
    passes = iter(range(4))

    async def _update_archive_stats(_db: Any, summed_at: int | None) -> int:
        handed.append(summed_at)
        if len(handed) == 3:
            raise RuntimeError("mongo unreachable")
        return len(handed) * 10

    async def _noop(*_args: Any) -> None:
        return None

    async def _get_database() -> FakeDatabase:
        return FakeDatabase()

    async def _sleep(_seconds: float) -> None:
        if next(passes) == 3:
            raise _StopLoop

    for name in (*_LABELS, *_QUIET_TASKS):
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "update_archive_stats", _update_archive_stats)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
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

    async def _noop(*_args: Any) -> None:
        return None

    async def _get_database() -> FakeDatabase:
        return db

    async def _sleep(_seconds: float) -> None:
        reported.append(REGISTRY.get_sample_value("archive_stored_bytes_total"))
        if len(reported) == 1:
            await db.archive_metadata.delete_one({"_id": "a2"})
            await db.archive_metadata.insert_one({"_id": "a3", "compressed_size_bytes": 70})
        if len(reported) == 4:
            raise _StopLoop

    for name in (*_LABELS, *_QUIET_TASKS):
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "update_archive_stats", update_archive_stats)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))
    monkeypatch.setattr(
        housekeeping,
        "datetime",
        SimpleNamespace(min=datetime.min.replace(tzinfo=timezone.utc), now=lambda _tz=None: next(clock)),
    )

    with pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop(AnalysisWorkerManager(num_workers=1))

    assert reported == [150, 150, 150, 170]
