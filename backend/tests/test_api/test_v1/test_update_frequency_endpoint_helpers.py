"""Unit tests for the update-frequency endpoints: cache keying, single-flight and the abandoned-request abort."""

import asyncio
import contextlib
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from app.api.deps import get_current_active_user, get_database
from app.api.v1.endpoints.analytics.update_frequency import (
    _DEFAULT_COMPARISON_WINDOW_DAYS,
    _LIVE_COMPARISON_BUDGET_SECONDS,
    _ROLLUP_COMPARISON_BUDGET_SECONDS,
    _comparison_cache_key,
    _lock_timings,
    _project_cache_key,
    get_project_update_frequency,
    get_update_frequency_comparison,
    router,
)
from app.core.cache import CacheTTL
from app.core.config import settings
from app.core.permissions import ALL_PERMISSIONS
from app.models.project import Project
from app.models.user import User
from app.schemas.analytics import ProjectUpdateSummary, UpdateFrequencyComparison, UpdateFrequencyMetrics
from app.services.rescan import build_rescan
from app.services.update_frequency import rank_summaries
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.analytics.update_frequency"


def _pkey(**overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "max_scans": 20,
        "window_days": None,
        "branch": None,
        "version_token": "1",
        "use_rollup": False,
    }
    return _project_cache_key("proj-1", **(kwargs | overrides))


class TestProjectCacheKey:
    def test_key_versions_on_completion_token(self):
        # A finished scan advances the token -> a new key -> no stale cache.
        assert _pkey(version_token="3") != _pkey(version_token="4")

    def test_key_distinguishes_branch_and_params(self):
        keys = {_pkey(), _pkey(branch="main"), _pkey(window_days=90), _pkey(use_rollup=True)}
        assert len(keys) == 4

    def test_key_stable_for_same_inputs(self):
        first = _pkey(window_days=90, branch="main")
        second = _pkey(window_days=90, branch="main")
        assert first == second

    def test_no_branch_and_a_branch_named_auto_get_different_keys(self):
        assert _pkey(branch=None) != _pkey(branch="auto")


def _ckey(scope: str = "scope-a", team: str | None = None, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {"window_days": 90, "use_rollup": False}
    return _comparison_cache_key(scope, team, **(kwargs | overrides))


class TestComparisonCacheKey:
    def test_key_separates_scope_team_and_params(self):
        keys = {_ckey(), _ckey(scope="scope-b"), _ckey(team="team-x"), _ckey(window_days=30)}
        assert len(keys) == 4

    def test_flipping_the_read_path_does_not_reuse_the_other_paths_answer(self):
        assert _ckey(use_rollup=False) != _ckey(use_rollup=True)

    def test_key_stable_for_same_inputs(self):
        first = _ckey()
        second = _ckey()
        assert first == second


class TestComparisonLockTimings:
    def test_the_lock_outlasts_the_waiter_on_both_paths(self):
        for use_rollup in (False, True):
            wait, ttl = _lock_timings(use_rollup)
            assert ttl > wait

    def test_the_slow_path_keeps_its_full_budget(self):
        assert _lock_timings(False)[0] == _LIVE_COMPARISON_BUDGET_SECONDS

    def test_the_rollup_waits_a_fraction_of_it(self):
        rollup_wait, _ttl = _lock_timings(True)
        assert rollup_wait == _ROLLUP_COMPARISON_BUDGET_SECONDS < _LIVE_COMPARISON_BUDGET_SECONDS


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


def _metrics(project_name: str) -> UpdateFrequencyMetrics:
    return UpdateFrequencyMetrics(
        project_id="p1",
        project_name=project_name,
        scan_count=2,
        time_range_days=1.0,
        first_scan_date="",
        last_scan_date="",
        total_updates=0,
        updates_per_scan=0.0,
        updates_per_month=None,
        patch_updates=0,
        minor_updates=0,
        major_updates=0,
        unknown_updates=0,
        granularity_ratio={},
        avg_days_between_scans=0.0,
        total_outdated_detected=0,
        outdated_resolved=0,
        trend_direction="unknown",
        trend_detail="",
        scan_timeline=[],
        slowest_packages=[],
        recent_updates=[],
    )


def _comparison(avg: float = 1.0) -> UpdateFrequencyComparison:
    return UpdateFrequencyComparison(projects=[], team_avg_updates_per_month=avg)


class TestComparisonEndpointCaching:
    def test_two_users_with_the_same_scope_share_one_computation(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison(3.5))
        db = _fake_db()

        with _endpoint_patched(cache, ["p1", "p2"], compute):
            first = asyncio.run(get_update_frequency_comparison(current_user=_user("user-1"), db=db))
            second = asyncio.run(get_update_frequency_comparison(current_user=_user("user-2"), db=db))

        assert compute.await_count == 1
        assert first.team_avg_updates_per_month == second.team_avg_updates_per_month == 3.5

    def test_different_scopes_do_not_share_an_entry(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1", "p2"], compute):
            asyncio.run(get_update_frequency_comparison(current_user=_user("user-1"), db=db))
        with _endpoint_patched(cache, ["p1"], compute):
            asyncio.run(get_update_frequency_comparison(current_user=_user("user-2"), db=db))

        assert compute.await_count == 2

    def test_cache_hit_issues_no_scan_count_and_no_project_query(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1", "p2"], compute) as repo_cls:
            asyncio.run(get_update_frequency_comparison(current_user=_user("user-1"), db=db))
            queries_after_miss = repo_cls.return_value.find_many_raw.await_count
            asyncio.run(get_update_frequency_comparison(current_user=_user("user-1"), db=db))
            queries_after_hit = repo_cls.return_value.find_many_raw.await_count

        assert db.scans.count_documents.await_count == 0
        assert queries_after_miss == 1
        assert queries_after_hit == 1

    def test_computation_runs_under_the_single_flight_lock(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            asyncio.run(get_update_frequency_comparison(current_user=_user("user-1"), db=db))

        assert len(cache.lock_calls) == 1
        assert cache.plain_sets == []
        call = cache.lock_calls[0]
        assert call["ttl_seconds"] == CacheTTL.UPDATE_FREQUENCY
        # A waiter must outlast the recompute, otherwise it starts a duplicate one.
        assert call["max_wait_seconds"] >= _LIVE_COMPARISON_BUDGET_SECONDS
        # The lock must outlast the waiter, otherwise a peer recomputes under the holder.
        assert call["lock_ttl_seconds"] > call["max_wait_seconds"]

    def test_a_caller_without_a_window_gets_the_documented_ninety_days(self):
        # The ranking only stays comparable while every project is measured over
        # the same span, so the default is part of the endpoint's contract.
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            asyncio.run(get_update_frequency_comparison(current_user=_user("u1"), db=db))

        assert compute.await_args.kwargs["window_days"] == 90
        # A scan-count cap selects nothing once a calendar window does; carrying
        # one would only fragment the cache across values that answer alike.
        assert "max_scans" not in compute.await_args.kwargs

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
                holder = asyncio.create_task(get_update_frequency_comparison(current_user=_user("u1"), db=db))
                await running.wait()
                waiter = asyncio.create_task(get_update_frequency_comparison(current_user=_user("u2"), db=db))
                return await asyncio.gather(holder, waiter)

        first, second = asyncio.run(_run())

        assert len(cache.fetches) == 1
        assert first.team_avg_updates_per_month == second.team_avg_updates_per_month == 4.0


class TestReadPathSelection:
    def test_the_flag_off_keeps_the_live_computation(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        rollup = AsyncMock(return_value={"projects": []})
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            with patch(f"{MODULE}._compute_comparison_from_rollup", rollup):
                asyncio.run(get_update_frequency_comparison(current_user=_user("u1"), db=db))

        assert compute.await_count == 1
        assert rollup.await_count == 0

    def test_the_flag_on_reads_the_rollup_instead(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison())
        rollup = AsyncMock(return_value={"projects": [], "pending_projects": 3})
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            with patch(f"{MODULE}._compute_comparison_from_rollup", rollup):
                with patch.object(settings, "UPDATE_FREQUENCY_USE_ROLLUP", True):
                    result = asyncio.run(get_update_frequency_comparison(current_user=_user("u1"), db=db))

        assert compute.await_count == 0
        assert result.pending_projects == 3
        assert rollup.await_args.kwargs["window_days"] == _DEFAULT_COMPARISON_WINDOW_DAYS

    def test_the_two_paths_do_not_share_a_cache_entry(self):
        cache = FakeCache()
        compute = AsyncMock(return_value=_comparison(1.0))
        rollup = AsyncMock(return_value={"projects": [], "team_avg_updates_per_month": 9.0})
        db = _fake_db()

        with _endpoint_patched(cache, ["p1"], compute):
            with patch(f"{MODULE}._compute_comparison_from_rollup", rollup):
                live = asyncio.run(get_update_frequency_comparison(current_user=_user("u1"), db=db))
                with patch.object(settings, "UPDATE_FREQUENCY_USE_ROLLUP", True):
                    rolled = asyncio.run(get_update_frequency_comparison(current_user=_user("u1"), db=db))

        assert (live.team_avg_updates_per_month, rolled.team_avg_updates_per_month) == (1.0, 9.0)


class TestProjectReadPathSelection:
    @staticmethod
    async def _run(rollup: Any, live: Any, **query: Any) -> UpdateFrequencyMetrics:
        db = await _scanned_db()
        with _project_patched(FakeCache(), live):
            with patch(f"{MODULE}._rollup_project_metrics", rollup):
                with patch.object(settings, "UPDATE_FREQUENCY_USE_ROLLUP", True):
                    return await _view(db, **query)

    @pytest.mark.asyncio
    async def test_the_windowed_default_view_reads_the_rollup(self):
        rollup = AsyncMock(return_value=_metrics("rollup"))
        live = AsyncMock(return_value=_metrics("live"))

        result = await self._run(rollup, live, window_days=90)

        assert result.project_name == "rollup"
        assert live.await_count == 0

    @pytest.mark.asyncio
    async def test_an_explicit_branch_stays_on_the_live_path(self):
        rollup = AsyncMock(return_value=_metrics("rollup"))
        live = AsyncMock(return_value=_metrics("live"))

        result = await self._run(rollup, live, window_days=90, branch="main")

        assert result.project_name == "live"
        assert rollup.await_count == 0

    @pytest.mark.asyncio
    async def test_the_max_scans_mode_stays_on_the_live_path(self):
        rollup = AsyncMock(return_value=_metrics("rollup"))
        live = AsyncMock(return_value=_metrics("live"))

        result = await self._run(rollup, live, max_scans=20)

        assert result.project_name == "live"
        assert rollup.await_count == 0

    @pytest.mark.asyncio
    async def test_a_project_the_ledger_cannot_answer_for_falls_back(self):
        rollup = AsyncMock(return_value=None)
        live = AsyncMock(return_value=_metrics("live"))

        result = await self._run(rollup, live, window_days=90)

        assert result.project_name == "live"
        assert rollup.await_count == 1


_NOW = datetime.now(tz=timezone.utc).replace(microsecond=0)


def _app(db: Any) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database] = lambda: db
    app.dependency_overrides[get_current_active_user] = lambda: _user("u1")
    return app


def _scan(scan_id: str, *, days_ago: float, branch: str = "main") -> dict[str, Any]:
    created_at = _NOW - timedelta(days=days_ago)
    return {
        "_id": scan_id,
        "project_id": "p1",
        "branch": branch,
        "commit_hash": f"commit-{scan_id}",
        "status": "completed",
        "is_rescan": False,
        "created_at": created_at,
        "completed_at": created_at + timedelta(minutes=5),
    }


def _finished_rescan(source: dict[str, Any]) -> dict[str, Any]:
    rescan = build_rescan(source).model_dump(by_alias=True)
    return rescan | {"status": "completed", "completed_at": _NOW}


async def _scanned_db() -> FakeDatabase:
    db = FakeDatabase()
    await db.scans.insert_many([_scan("s1", days_ago=3), _scan("s2", days_ago=2)])
    return db


@contextmanager
def _project_patched(cache: FakeCache, live: Any):
    project = Project(id="p1", name="Project One")
    with patch(f"{MODULE}.cache_service", cache):
        with patch(f"{MODULE}.check_project_access", AsyncMock(return_value=project)):
            with patch(f"{MODULE}.compute_update_frequency", live):
                yield


async def _view(db: Any, request: FakeRequest | None = None, **query: Any) -> UpdateFrequencyMetrics:
    return await get_project_update_frequency(
        project_id="p1", request=request or FakeRequest(), current_user=_user("u1"), db=db, **query
    )


class TestProjectEndpointCaching:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("unread", ["other-branch", "rescan"])
    async def test_a_scan_the_walk_does_not_read_keeps_the_entry(self, unread: str):
        db = await _scanned_db()
        live = AsyncMock(return_value=_metrics("live"))
        scan = (
            _scan("s3", days_ago=1, branch="feature")
            if unread == "other-branch"
            else _finished_rescan(_scan("s2", days_ago=2))
        )

        with _project_patched(FakeCache(), live):
            await _view(db)
            await db.scans.insert_one(scan)
            await _view(db)

        assert live.await_count == 1

    @pytest.mark.asyncio
    async def test_a_new_scan_on_the_analysed_branch_misses(self):
        db = await _scanned_db()
        live = AsyncMock(return_value=_metrics("live"))

        with _project_patched(FakeCache(), live):
            await _view(db)
            await db.scans.insert_one(_scan("s3", days_ago=1))
            await _view(db)

        assert live.await_count == 2

    @pytest.mark.asyncio
    async def test_a_re_finalised_scan_misses(self):
        db = await _scanned_db()
        live = AsyncMock(return_value=_metrics("live"))

        with _project_patched(FakeCache(), live):
            await _view(db)
            await db.scans.update_one({"_id": "s1"}, {"$set": {"completed_at": _NOW}})
            await _view(db)

        assert live.await_count == 2

    @pytest.mark.asyncio
    async def test_the_walk_gets_the_elected_branch(self):
        db = await _scanned_db()
        live = AsyncMock(return_value=_metrics("live"))

        with _project_patched(FakeCache(), live):
            await _view(db)

        assert live.await_args.kwargs["branch"] == "main"

    @pytest.mark.asyncio
    async def test_a_branch_named_auto_is_not_the_default_view(self):
        db = await _scanned_db()
        live = AsyncMock(side_effect=[_metrics("default"), _metrics("auto")])

        with _project_patched(FakeCache(), live):
            default = await _view(db)
            auto = await _view(db, branch="auto")

        assert (default.project_name, auto.project_name) == ("default", "auto")

    @pytest.mark.asyncio
    async def test_concurrent_views_share_one_walk(self):
        db = await _scanned_db()
        cache = FakeCache()

        async def _slow(**_kwargs: Any) -> UpdateFrequencyMetrics:
            await asyncio.sleep(0.05)
            return _metrics("live")

        live = AsyncMock(side_effect=_slow)
        with _project_patched(cache, live):
            await asyncio.gather(_view(db), _view(db))

        assert live.await_count == 1
        assert cache.lock_calls[0]["reraise_fetch_errors"] is True

    @pytest.mark.asyncio
    async def test_an_empty_branch_is_rejected(self):
        db = await _scanned_db()
        live = AsyncMock(return_value=_metrics("live"))

        with _project_patched(FakeCache(), live):
            async with AsyncClient(transport=ASGITransport(app=_app(db)), base_url="http://test") as client:
                response = await client.get("/projects/p1/update-frequency", params={"branch": ""})

        assert response.status_code == 422
        assert live.await_count == 0


class TestProjectEndpointDisconnect:
    @pytest.mark.asyncio
    async def test_a_client_leaving_mid_walk_cancels_it(self):
        db = await _scanned_db()
        cache = FakeCache()
        cancelled = asyncio.Event()

        async def _slow(**_kwargs: Any) -> UpdateFrequencyMetrics:
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return _metrics("live")

        # Stay connected for the first poll so the abort lands after the work began.
        request = FakeRequest(disconnect_after_polls=2)
        started = time.monotonic()
        with patch(f"{MODULE}._DISCONNECT_POLL_SECONDS", 0.01):
            with _project_patched(cache, AsyncMock(side_effect=_slow)):
                with pytest.raises(HTTPException) as excinfo:
                    await _view(db, request)

        assert excinfo.value.status_code == 499
        assert cancelled.is_set()
        assert time.monotonic() - started < 5
        assert cache.store == {}

    @pytest.mark.asyncio
    async def test_outer_cancellation_does_not_orphan_the_walk(self):
        db = await _scanned_db()
        running = asyncio.Event()
        cancelled = asyncio.Event()

        async def _slow(**_kwargs: Any) -> UpdateFrequencyMetrics:
            running.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return _metrics("live")

        with patch(f"{MODULE}._DISCONNECT_POLL_SECONDS", 0.01):
            with _project_patched(FakeCache(), AsyncMock(side_effect=_slow)):
                request_task = asyncio.create_task(_view(db))
                await running.wait()
                request_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await request_task
                # Checked before the loop ends: teardown would cancel a leaked walk too and mask it.
                assert cancelled.is_set()


def _summary(project_id: str, name: str, team_id: str, rate: float) -> ProjectUpdateSummary:
    return ProjectUpdateSummary(
        project_id=project_id,
        project_name=name,
        teams=[{"id": team_id, "name": team_id}],
        data_status="ready",
        branch="main",
        window_days=_DEFAULT_COMPARISON_WINDOW_DAYS,
        scan_count=5,
        updates_per_month=rate,
        update_coverage_pct=rate * 10,
        patch_ratio=0.5,
        trend_direction="stable",
        total_updates=int(rate * 3),
        total_outdated=4,
        last_scan_date=_NOW.isoformat(),
    )


_TEAM_X_SUMMARY = _summary("p1", "Alpha", "team-x", 2.0)
_TEAM_Y_SUMMARY = _summary("p2", "Beta", "team-y", 6.0)


async def _teamed_db() -> FakeDatabase:
    db = FakeDatabase()
    await db.teams.insert_many([{"_id": "team-x", "name": "team-x"}, {"_id": "team-y", "name": "team-y"}])
    await db.projects.insert_many(
        [
            {"_id": "p1", "name": "Alpha", "team_ids": ["team-x"]},
            {"_id": "p2", "name": "Beta", "team_ids": ["team-y"]},
        ]
    )
    return db


async def _rank_what_was_asked_for(projects: list[dict[str, Any]], **_kwargs: Any) -> UpdateFrequencyComparison:
    asked = {p["_id"] for p in projects}
    return rank_summaries([s for s in (_TEAM_X_SUMMARY, _TEAM_Y_SUMMARY) if s.project_id in asked])


@contextmanager
def _comparison_patched(cache: FakeCache, compute: Any):
    with patch(f"{MODULE}.cache_service", cache):
        with patch(f"{MODULE}.get_user_project_ids", AsyncMock(return_value=["p1", "p2"])):
            with patch(f"{MODULE}.compute_update_frequency_comparison", compute):
                yield


class TestComparisonTeamView:
    @pytest.mark.asyncio
    async def test_a_team_view_is_derived_from_the_cached_all_teams_ranking(self):
        db = await _teamed_db()
        compute = AsyncMock(side_effect=_rank_what_was_asked_for)

        with _comparison_patched(FakeCache(), compute):
            async with AsyncClient(transport=ASGITransport(app=_app(db)), base_url="http://test") as client:
                everyone = await client.get("/update-frequency/comparison")
                team = await client.get("/update-frequency/comparison", params={"team_id": "team-x"})

        assert everyone.status_code == team.status_code == 200, team.text
        assert compute.await_count == 1
        assert UpdateFrequencyComparison(**team.json()) == rank_summaries([_TEAM_X_SUMMARY])

    @pytest.mark.asyncio
    async def test_a_team_view_without_a_cached_ranking_computes_only_the_team(self):
        db = await _teamed_db()
        compute = AsyncMock(side_effect=_rank_what_was_asked_for)

        with _comparison_patched(FakeCache(), compute):
            async with AsyncClient(transport=ASGITransport(app=_app(db)), base_url="http://test") as client:
                team = await client.get("/update-frequency/comparison", params={"team_id": "team-x"})

        assert team.status_code == 200, team.text
        assert [p["_id"] for p in compute.await_args.kwargs["projects"]] == ["p1"]

    @pytest.mark.asyncio
    async def test_a_team_named_all_does_not_blank_the_all_teams_view(self):
        db = await _teamed_db()
        compute = AsyncMock(side_effect=_rank_what_was_asked_for)

        with _comparison_patched(FakeCache(), compute):
            async with AsyncClient(transport=ASGITransport(app=_app(db)), base_url="http://test") as client:
                named_all = await client.get("/update-frequency/comparison", params={"team_id": "all"})
                everyone = await client.get("/update-frequency/comparison")

        assert named_all.json()["projects"] == []
        assert [p["project_id"] for p in everyone.json()["projects"]] == ["p2", "p1"]


async def _get_then_disconnect(app: FastAPI, path: str) -> list[dict[str, Any]]:
    """Drive the ASGI app for a client that goes away right after sending its request."""
    messages = iter([{"type": "http.request", "body": b"", "more_body": False}])

    async def receive() -> dict[str, Any]:
        return next(messages, {"type": "http.disconnect"})

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [],
        "server": ("test", 80),
        "client": ("test", 1),
    }
    await app(scope, receive, send)
    return sent


class TestComparisonLeaderDisconnect:
    @pytest.mark.asyncio
    async def test_a_leader_whose_client_left_still_publishes_for_the_next_caller(self):
        db = await _teamed_db()
        cache = FakeCache()

        async def _slow(**_kwargs: Any) -> UpdateFrequencyComparison:
            await asyncio.sleep(0.05)
            return rank_summaries([_TEAM_X_SUMMARY, _TEAM_Y_SUMMARY])

        compute = AsyncMock(side_effect=_slow)
        app = _app(db)
        with patch(f"{MODULE}._DISCONNECT_POLL_SECONDS", 0.01):
            with _comparison_patched(cache, compute):
                sent = await _get_then_disconnect(app, "/update-frequency/comparison")
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                    returning = await client.get("/update-frequency/comparison")

        assert sent[0]["status"] == 200
        assert returning.status_code == 200, returning.text
        assert compute.await_count == 1
