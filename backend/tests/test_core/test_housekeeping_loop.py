"""A failing stuck-scan recovery, re-scan check, daily sweep or branch sync is logged under its label, and the
housekeeping loop runs the others."""

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
