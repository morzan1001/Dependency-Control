"""Each housekeeping iteration works the waiver recalculation queue off, so a change a restart interrupted, or a
waiver that expired, is recalculated within one interval."""

from types import SimpleNamespace
from typing import Any

import pytest

from app.core import housekeeping
from tests.mocks.fake_mongo import FakeDatabase

_OTHER_TASKS = (
    "recover_stuck_scans",
    "check_scheduled_rescans",
    "update_db_stats",
    "update_archive_stats",
    "update_cache_stats",
    "run_housekeeping",
    "sync_branch_status",
    "reconcile_update_frequency_ledger",
)


class _StopLoop(Exception):
    """Breaks out of the endless housekeeping loop."""


async def _one_iteration(monkeypatch: pytest.MonkeyPatch, recalc: Any) -> FakeDatabase:
    db = FakeDatabase()

    async def _noop(*_args: Any, **_kwargs: Any) -> None:
        return None

    async def _get_database() -> FakeDatabase:
        return db

    async def _sleep(_seconds: float) -> None:
        raise _StopLoop

    for name in _OTHER_TASKS:
        monkeypatch.setattr(housekeeping, name, _noop)
    monkeypatch.setattr(housekeeping, "get_database", _get_database)
    monkeypatch.setattr(housekeeping, "run_waiver_recalc", recalc)
    monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))
    with pytest.raises(_StopLoop):
        await housekeeping.housekeeping_loop()
    return db


@pytest.mark.asyncio
async def test_every_iteration_runs_the_waiver_recalculation(monkeypatch: pytest.MonkeyPatch):
    ran: list[Any] = []

    async def _recalc(db: Any) -> None:
        ran.append(db)

    db = await _one_iteration(monkeypatch, _recalc)

    assert ran == [db]


@pytest.mark.asyncio
async def test_a_failing_recalculation_leaves_the_loop_running(monkeypatch: pytest.MonkeyPatch):
    async def _recalc(_db: Any) -> None:
        raise RuntimeError("mongo unreachable")

    await _one_iteration(monkeypatch, _recalc)
