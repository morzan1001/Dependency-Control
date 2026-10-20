import logging
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import housekeeping
from app.core.worker import AnalysisWorkerManager
from tests.mocks.fake_mongo import FakeDatabase

_LABELS = {
    "recover_stuck_scans": "Stuck scan recovery",
    "check_scheduled_rescans": "Scheduled re-scan check",
    "run_housekeeping": "Housekeeping task",
    "sync_branch_status": "Branch status sync",
}
_QUIET_TASKS = (
    "update_db_stats",
    "update_archive_stats",
    "update_cache_stats",
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
    assert [record.getMessage() for record in caplog.records] == [f"{_LABELS[failing]} failed: mongo unreachable"]


@pytest.mark.asyncio
async def test_each_pass_hands_the_archive_count_its_bytes_were_summed_at_to_the_next(monkeypatch):
    handed: list[int | None] = []
    passes = iter(range(3))

    async def _update_archive_stats(_db: Any, summed_at: int | None) -> int:
        handed.append(summed_at)
        return len(handed) * 10

    async def _noop(*_args: Any) -> None:
        return None

    async def _get_database() -> FakeDatabase:
        return FakeDatabase()

    async def _sleep(_seconds: float) -> None:
        if next(passes) == 2:
            raise _StopLoop

    for name in (*_LABELS, *_QUIET_TASKS):
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "update_archive_stats", _update_archive_stats)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))

    with pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop(AnalysisWorkerManager(num_workers=1))

    assert handed == [None, 10, 20]
