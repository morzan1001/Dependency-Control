"""When the housekeeping loop lets the update-frequency reconcile run at all."""

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import housekeeping
from app.core.config import settings
from app.core.constants import HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC as QUIET_HOUR
from tests.mocks.fake_mongo import FakeDatabase

_NEVER = datetime.min.replace(tzinfo=timezone.utc)
_LOUD_HOUR = (QUIET_HOUR + 12) % 24


class _StopLoop(Exception):
    """Breaks out of the endless housekeeping loop."""


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 6, day, hour, minute, tzinfo=timezone.utc)


class TestKillSwitch:
    @pytest.fixture
    def ran(self, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        calls: list[str] = []

        async def _get_database() -> FakeDatabase:
            return FakeDatabase()

        async def _run(_db: Any) -> None:
            calls.append("run")

        monkeypatch.setattr(housekeeping, "get_database", _get_database)
        monkeypatch.setattr(housekeeping, "run_update_frequency_reconcile", _run)
        return calls

    @pytest.mark.asyncio
    async def test_the_reconcile_stays_off_until_its_own_flag_is_set(self, ran: list[str]):
        assert settings.UPDATE_FREQUENCY_ROLLUP_ENABLED is True

        await housekeeping.reconcile_update_frequency_ledger()

        assert ran == []

    @pytest.mark.asyncio
    async def test_the_flag_turns_it_on_without_touching_the_writer(
        self, ran: list[str], monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(settings, "UPDATE_FREQUENCY_RECONCILE_ENABLED", True)

        await housekeeping.reconcile_update_frequency_ledger()

        assert ran == ["run"]


class TestNightlySchedule:
    def test_a_deploy_outside_the_quiet_hour_starts_no_run(self):
        assert not housekeeping._reconcile_due(_at(1, _LOUD_HOUR), _NEVER)

    def test_a_pod_that_never_ran_one_takes_the_first_quiet_hour(self):
        assert housekeeping._reconcile_due(_at(1, QUIET_HOUR), _NEVER)

    def test_the_same_night_is_not_reconciled_twice(self):
        assert not housekeeping._reconcile_due(_at(1, QUIET_HOUR, 55), _at(1, QUIET_HOUR, 5))

    def test_the_next_night_is(self):
        assert housekeeping._reconcile_due(_at(2, QUIET_HOUR), _at(1, QUIET_HOUR, 5))


class TestLoopWiring:
    @pytest.fixture
    def loop_at(self, monkeypatch: pytest.MonkeyPatch):
        """Run two iterations of the loop at a frozen clock, doing nothing but the reconcile."""
        calls: list[str] = []

        async def _noop(*_args: Any, **_kwargs: Any) -> None:
            return None

        for name in (
            "recover_stuck_scans",
            "check_scheduled_rescans",
            "update_db_stats",
            "update_archive_stats",
            "update_cache_stats",
            "get_database",
            "run_housekeeping",
            "sync_branch_status",
        ):
            monkeypatch.setattr(housekeeping, name, _noop)

        async def _reconcile() -> None:
            calls.append("reconcile")

        monkeypatch.setattr(housekeeping, "reconcile_update_frequency_ledger", _reconcile)

        async def _run(now: datetime) -> list[str]:
            iterations = 0

            async def _sleep(_seconds: float) -> None:
                nonlocal iterations
                iterations += 1
                if iterations == 2:
                    raise _StopLoop

            monkeypatch.setattr(housekeeping, "asyncio", SimpleNamespace(sleep=_sleep))
            monkeypatch.setattr(
                housekeeping,
                "datetime",
                SimpleNamespace(min=_NEVER, now=lambda _tz=None: now),
            )
            with pytest.raises(_StopLoop):
                await housekeeping.housekeeping_loop()
            return calls

        return _run

    @pytest.mark.asyncio
    async def test_a_daytime_rollout_does_not_reconcile(self, loop_at: Any):
        assert await loop_at(_at(1, _LOUD_HOUR)) == []

    @pytest.mark.asyncio
    async def test_the_quiet_hour_does(self, loop_at: Any):
        assert await loop_at(_at(1, QUIET_HOUR)) == ["reconcile"]
