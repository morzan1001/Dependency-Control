"""Unit tests for the update-frequency endpoint helpers: cache keying, single-flight and the abandoned-request abort."""

import asyncio
import contextlib
import time
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.analytics.update_frequency import (
    _COMPARISON_COMPUTE_BUDGET_SECONDS,
    _DEFAULT_COMPARISON_WINDOW_DAYS,
    _comparison_cache_key,
    _project_cache_key,
    _scope_hash,
    get_update_frequency_comparison,
)
from app.core.cache import CacheTTL
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User
from app.schemas.analytics import UpdateFrequencyComparison

MODULE = "app.api.v1.endpoints.analytics.update_frequency"


class TestProjectCacheKey:
    def test_key_versions_on_completion_token(self):
        # A finished scan advances the token -> a new key -> no stale cache.
        base = _project_cache_key("proj-1", max_scans=20, window_days=None, branch=None, version_token="3")
        after_scan = _project_cache_key("proj-1", max_scans=20, window_days=None, branch=None, version_token="4")
        assert base != after_scan

    def test_key_distinguishes_branch_and_params(self):
        auto = _project_cache_key("proj-1", max_scans=20, window_days=None, branch=None, version_token="1")
        main = _project_cache_key("proj-1", max_scans=20, window_days=None, branch="main", version_token="1")
        windowed = _project_cache_key("proj-1", max_scans=20, window_days=90, branch=None, version_token="1")
        assert len({auto, main, windowed}) == 3

    def test_key_stable_for_same_inputs(self):
        a = _project_cache_key("proj-1", max_scans=20, window_days=90, branch="main", version_token="1")
        b = _project_cache_key("proj-1", max_scans=20, window_days=90, branch="main", version_token="1")
        assert a == b


class TestScopeHash:
    def test_same_project_set_hashes_equal_regardless_of_order(self):
        assert _scope_hash(["a", "b", "c"]) == _scope_hash(["c", "a", "b"])

    def test_different_project_set_hashes_differently(self):
        assert _scope_hash(["a", "b"]) != _scope_hash(["a", "b", "c"])


class TestComparisonCacheKey:
    def test_key_separates_scope_team_and_params(self):
        base = _comparison_cache_key("scope-a", "all", max_scans=20, window_days=None)
        other_scope = _comparison_cache_key("scope-b", "all", max_scans=20, window_days=None)
        team = _comparison_cache_key("scope-a", "team-x", max_scans=20, window_days=None)
        scans = _comparison_cache_key("scope-a", "all", max_scans=50, window_days=None)
        window = _comparison_cache_key("scope-a", "all", max_scans=20, window_days=90)
        assert len({base, other_scope, team, scans, window}) == 5

    def test_key_stable_for_same_inputs(self):
        a = _comparison_cache_key("scope-a", "all", max_scans=20, window_days=90)
        b = _comparison_cache_key("scope-a", "all", max_scans=20, window_days=90)
        assert a == b


_FAKE_LOCK_POLL_SECONDS = 0.01


class FakeCache:
    """In-process ``cache_service`` reproducing the single-flight contract without Redis."""

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.lock_calls: list[dict[str, Any]] = []
        self.plain_sets: list[str] = []
        self.fetches: list[str] = []
        self._held: set[str] = set()

    async def get(self, key: str) -> Any | None:
        return self.store.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> bool:
        self.plain_sets.append(key)
        self.store[key] = value
        return True

    async def get_or_fetch_with_lock(
        self,
        key: str,
        fetch_fn: Any,
        ttl_seconds: int | None = None,
        lock_ttl_seconds: int = 30,
        max_wait_seconds: float = 5.0,
        reraise_fetch_errors: bool = False,
    ) -> Any | None:
        self.lock_calls.append(
            {
                "key": key,
                "ttl_seconds": ttl_seconds,
                "lock_ttl_seconds": lock_ttl_seconds,
                "max_wait_seconds": max_wait_seconds,
                "reraise_fetch_errors": reraise_fetch_errors,
            }
        )
        deadline = time.monotonic() + max_wait_seconds
        while time.monotonic() < deadline:
            cached = await self.get(key)
            if cached is not None:
                return cached
            if key not in self._held:
                return await self._fetch_holding_lock(key, fetch_fn, reraise_fetch_errors)
            await asyncio.sleep(_FAKE_LOCK_POLL_SECONDS)
        return await fetch_fn()

    async def _fetch_holding_lock(self, key: str, fetch_fn: Any, reraise_fetch_errors: bool) -> Any | None:
        self._held.add(key)
        self.fetches.append(key)
        try:
            try:
                data = await fetch_fn()
            except Exception:
                if reraise_fetch_errors:
                    raise
                return None
            # Negative-cache a failed fetch so peers stop retrying it, as CacheService does.
            self.store[key] = data if data is not None else {}
            return data
        finally:
            self._held.discard(key)


class UnavailableCache(FakeCache):
    """Redis down and the fetch itself failing: the lock helper yields None."""

    async def get_or_fetch_with_lock(self, key: str, fetch_fn: Any, **_kwargs: Any) -> Any | None:
        return None


class FakeRequest:
    def __init__(self, disconnect_after_polls: int | None = None) -> None:
        self.disconnect_after_polls = disconnect_after_polls
        self.polls = 0

    async def is_disconnected(self) -> bool:
        self.polls += 1
        return self.disconnect_after_polls is not None and self.polls >= self.disconnect_after_polls


def _user(user_id: str) -> User:
    return User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@test.com",
        permissions=list(ALL_PERMISSIONS),
    )


def _fake_db() -> MagicMock:
    db = MagicMock()
    db.scans.count_documents = AsyncMock(return_value=7)
    return db


@contextmanager
def _endpoint_patched(cache: FakeCache, project_ids: list[str], compute: Any):
    projects_raw = [{"_id": pid, "name": pid} for pid in project_ids]
    with patch(f"{MODULE}.cache_service", cache):
        with patch(f"{MODULE}.get_user_project_ids", AsyncMock(return_value=project_ids)):
            with patch(f"{MODULE}.ProjectRepository") as repo_cls:
                with patch(f"{MODULE}.compute_update_frequency_comparison", compute):
                    repo_cls.return_value.find_many_raw = AsyncMock(return_value=projects_raw)
                    yield repo_cls


def _comparison(avg: float = 1.0) -> UpdateFrequencyComparison:
    return UpdateFrequencyComparison(projects=[], team_avg_updates_per_month=avg)


class TestComparisonEndpointCaching:
    def test_two_users_with_the_same_scope_share_one_computation(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison(3.5))
        db = _fake_db()

        with _endpoint_patched(cache, ["p1", "p2"], compute):
            first = asyncio.run(
                get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-1"), db=db)
            )
            second = asyncio.run(
                get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-2"), db=db)
            )

        assert compute.await_count == 1
        assert first.team_avg_updates_per_month == second.team_avg_updates_per_month == 3.5

    def test_different_scopes_do_not_share_an_entry(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1", "p2"], compute):
            asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-1"), db=db))
        with _endpoint_patched(cache, ["p1"], compute):
            asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-2"), db=db))

        assert compute.await_count == 2

    def test_cache_hit_issues_no_scan_count_and_no_project_query(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1", "p2"], compute) as repo_cls:
            asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-1"), db=db))
            queries_after_miss = repo_cls.return_value.find_many_raw.await_count
            asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-1"), db=db))
            queries_after_hit = repo_cls.return_value.find_many_raw.await_count

        assert db.scans.count_documents.await_count == 0
        assert queries_after_miss == 1
        assert queries_after_hit == 1

    def test_computation_runs_under_the_single_flight_lock(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-1"), db=db))

        assert len(cache.lock_calls) == 1
        assert cache.plain_sets == []
        call = cache.lock_calls[0]
        assert call["ttl_seconds"] == CacheTTL.UPDATE_FREQUENCY
        # A waiter must outlast the recompute, otherwise it starts a duplicate one.
        assert call["max_wait_seconds"] >= _COMPARISON_COMPUTE_BUDGET_SECONDS
        # The lock must outlast the waiter, otherwise a peer recomputes under the holder.
        assert call["lock_ttl_seconds"] > call["max_wait_seconds"]

    def test_a_caller_without_a_window_gets_the_documented_ninety_days(self):
        # The ranking only stays comparable while every project is measured over
        # the same span, so the default is part of the endpoint's contract.
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("u1"), db=db))

        assert compute.await_args.kwargs["window_days"] == 90

    def test_negatively_cached_entry_reports_unavailable_without_recomputing(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()
        key = _comparison_cache_key(
            _scope_hash(["p1"]), "all", max_scans=20, window_days=_DEFAULT_COMPARISON_WINDOW_DAYS
        )
        cache.store[key] = {}

        with _endpoint_patched(cache, ["p1"], compute):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("u1"), db=db))

        assert excinfo.value.status_code == 503
        assert compute.await_count == 0

    def test_unavailable_cache_reports_503(self):
        cache = UnavailableCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("u1"), db=db))

        assert excinfo.value.status_code == 503

    def test_concurrent_callers_wait_instead_of_recomputing(self):
        cache = FakeCache()
        db = _fake_db()
        running = asyncio.Event()

        async def _slow(**_kwargs: Any) -> UpdateFrequencyComparison:
            running.set()
            await asyncio.sleep(0.05)
            return _comparison(4.0)

        async def _run() -> tuple[Any, Any]:
            with _endpoint_patched(cache, ["p1"], _slow):
                holder = asyncio.create_task(
                    get_update_frequency_comparison(request=FakeRequest(), current_user=_user("u1"), db=db)
                )
                await running.wait()
                waiter = asyncio.create_task(
                    get_update_frequency_comparison(request=FakeRequest(), current_user=_user("u2"), db=db)
                )
                return await asyncio.gather(holder, waiter)

        first, second = asyncio.run(_run())

        assert len(cache.fetches) == 1
        assert first.team_avg_updates_per_month == second.team_avg_updates_per_month == 4.0

    def test_waiter_recomputes_when_the_holder_is_cancelled(self):
        cache = FakeCache()
        db = _fake_db()
        running = asyncio.Event()
        holder_cancelled = asyncio.Event()
        attempts = 0

        async def _compute(**_kwargs: Any) -> UpdateFrequencyComparison:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                running.set()
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    holder_cancelled.set()
                    raise
            return _comparison(2.5)

        async def _run() -> Any:
            with patch(f"{MODULE}._DISCONNECT_POLL_SECONDS", 0.01):
                with _endpoint_patched(cache, ["p1"], _compute):
                    holder = asyncio.create_task(
                        get_update_frequency_comparison(request=FakeRequest(), current_user=_user("u1"), db=db)
                    )
                    await running.wait()
                    waiter = asyncio.create_task(
                        get_update_frequency_comparison(request=FakeRequest(), current_user=_user("u2"), db=db)
                    )
                    while len(cache.lock_calls) < 2:
                        await asyncio.sleep(0)
                    holder.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await holder
                    return await waiter

        result = asyncio.run(_run())

        # Cancelling the request task must kill the computation it started, not orphan it.
        assert holder_cancelled.is_set()
        assert attempts == 2
        assert result.team_avg_updates_per_month == 2.5

    def test_team_filter_uses_its_own_entry(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1", "p2"], compute):
            asyncio.run(get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-1"), db=db))
            asyncio.run(
                get_update_frequency_comparison(
                    request=FakeRequest(), current_user=_user("user-1"), db=db, team_id="team-x"
                )
            )

        assert compute.await_count == 2


class TestComparisonEndpointDisconnect:
    def test_client_disconnecting_mid_computation_cancels_it(self):
        cache = FakeCache()
        running = asyncio.Event()
        cancelled = asyncio.Event()

        async def _slow(**_kwargs: Any) -> UpdateFrequencyComparison:
            running.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return _comparison()

        db = _fake_db()
        # Stay connected for the first poll so the abort lands after the work began.
        request = FakeRequest(disconnect_after_polls=2)

        async def _run() -> None:
            with patch(f"{MODULE}._DISCONNECT_POLL_SECONDS", 0.01):
                with _endpoint_patched(cache, ["p1"], _slow):
                    await get_update_frequency_comparison(request=request, current_user=_user("user-1"), db=db)

        started = time.monotonic()
        with pytest.raises(HTTPException) as excinfo:
            asyncio.run(_run())

        assert excinfo.value.status_code == 499
        assert request.polls >= 2
        assert running.is_set()
        assert cancelled.is_set()
        assert time.monotonic() - started < 5
        assert cache.store == {}

    def test_outer_cancellation_does_not_orphan_the_computation(self):
        cache = FakeCache()
        running = asyncio.Event()
        cancelled = asyncio.Event()

        async def _slow(**_kwargs: Any) -> UpdateFrequencyComparison:
            running.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return _comparison()

        db = _fake_db()

        async def _run() -> bool:
            with patch(f"{MODULE}._DISCONNECT_POLL_SECONDS", 0.01):
                with _endpoint_patched(cache, ["p1"], _slow):
                    request_task = asyncio.create_task(
                        get_update_frequency_comparison(request=FakeRequest(), current_user=_user("user-1"), db=db)
                    )
                    # running.set() fires inside the inner task, so _await_or_abort is
                    # already parked in asyncio.wait by the time this returns.
                    await running.wait()
                    request_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await request_task
                    # Checked here, not after asyncio.run(): loop teardown would cancel
                    # a leaked computation too and mask the leak.
                    return cancelled.is_set()

        assert asyncio.run(_run()) is True

    def test_connected_client_gets_the_result(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison(2.0))
        db = _fake_db()
        request = FakeRequest()

        with patch(f"{MODULE}._DISCONNECT_POLL_SECONDS", 0.01):
            with _endpoint_patched(cache, ["p1"], compute):
                result = asyncio.run(
                    get_update_frequency_comparison(request=request, current_user=_user("user-1"), db=db)
                )

        assert result.team_avg_updates_per_month == 2.0
