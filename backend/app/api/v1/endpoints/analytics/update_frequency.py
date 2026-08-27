"""Analytics update-frequency endpoints."""

import asyncio
import contextlib
import hashlib
import logging
from collections.abc import Coroutine
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import httpx
from fastapi import HTTPException, Query, Request

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import SCAN_USABLE_STATUSES
from app.core.http_utils import InstrumentedAsyncClient
from app.core.permissions import Permissions
from app.repositories import (
    AnalysisResultRepository,
    DependencyRepository,
    ProjectRepository,
    ScanRepository,
)
from app.schemas.analytics import (
    UpdateFrequencyComparison,
    UpdateFrequencyMetrics,
)
from app.services.release_history import (
    DepsDevReleaseHistoryFetcher,
    ReleaseHistoryFetcher,
)
from app.services.update_frequency import (
    compute_update_frequency,
    compute_update_frequency_comparison,
)

from ._shared import _MSG_ACCESS_DENIED

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_DISCONNECT_POLL_SECONDS = 1.0

# Worst-case wall time of one comparison recompute over the largest tenant.
_COMPARISON_COMPUTE_BUDGET_SECONDS = 240.0
# A waiter must outlast the recompute or it starts a duplicate one; the lock must
# outlast it too, or a second caller recomputes while the holder is still working.
_COMPARISON_LOCK_WAIT_SECONDS = _COMPARISON_COMPUTE_BUDGET_SECONDS
_COMPARISON_LOCK_TTL_SECONDS = int(_COMPARISON_COMPUTE_BUDGET_SECONDS) + 60


def _resolve_since(window_days: int | None) -> datetime | None:
    """Translate ``window_days`` into a ``since`` UTC cutoff."""
    if window_days is None:
        return None
    return datetime.now(tz=timezone.utc) - timedelta(days=window_days)


async def _await_or_abort[T](request: Request, coro: Coroutine[Any, Any, T]) -> T:
    """Drop the computation once the caller is gone instead of running it to completion."""
    task = asyncio.ensure_future(coro)
    try:
        while True:
            done, _pending = await asyncio.wait({task}, timeout=_DISCONNECT_POLL_SECONDS)
            if done:
                return task.result()
            if await request.is_disconnected():
                raise HTTPException(status_code=499, detail="Client disconnected")
    finally:
        # asyncio.wait() leaves its futures running, so the task outlives us on any
        # exit path -- including an outer cancellation at shutdown -- unless killed here.
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


def _project_cache_key(
    project_id: str,
    *,
    max_scans: int,
    window_days: int | None,
    branch: str | None,
    version_token: str,
) -> str:
    """Cache key carrying a completion-monotonic token so a finished scan misses the cache."""
    return (
        f"{CacheKeys.update_frequency(project_id)}"
        f":m{max_scans}:w{window_days or 0}:b{branch or 'auto'}:v{version_token}"
    )


def _scope_hash(project_ids: list[str]) -> str:
    """Digest of the caller's visible projects: the authorization boundary, shared by equal scopes."""
    return hashlib.md5(",".join(sorted(project_ids)).encode(), usedforsecurity=False).hexdigest()[:16]


def _comparison_cache_key(
    scope_hash: str,
    team_id: str,
    *,
    max_scans: int,
    window_days: int | None,
) -> str:
    """Cache key shared by every caller with the same visible-project scope."""
    base = CacheKeys.update_frequency_comparison(scope_hash, team_id)
    return f"{base}:m{max_scans}:w{window_days or 0}"


async def _project_scan_version(db: DatabaseDep, project_id: str) -> str:
    """Completed-scan count: a cache token monotonic per completion, unlike max(created_at) on out-of-order finishes."""
    count = await db.scans.count_documents({"project_id": project_id, "status": {"$in": SCAN_USABLE_STATUSES}})
    return str(count)


def _build_release_fetcher() -> ReleaseHistoryFetcher:
    """Production deps.dev fetcher wired to Redis + httpx, built per request."""

    async def cache_get(key: str) -> Any | None:
        return await cache_service.get(key)

    async def cache_set(key: str, value: Any, ttl_seconds: int) -> None:
        await cache_service.set(key, value, ttl_seconds=ttl_seconds)

    async def http_fetch(url: str) -> dict[str, Any] | None:
        try:
            async with InstrumentedAsyncClient("deps.dev API", timeout=10.0) as client:
                response = await client.get(url, follow_redirects=True)
                if response.status_code == 200:
                    payload: dict[str, Any] = response.json()
                    return payload
                return None
        except (httpx.TimeoutException, httpx.ConnectError):
            return None
        except Exception:
            logger.debug("deps.dev release-history fetch failed", exc_info=True)
            return None

    return DepsDevReleaseHistoryFetcher(
        cache_get=cache_get,
        cache_set=cache_set,
        http_fetch=http_fetch,
        cache_key_builder=CacheKeys.release_history,
        cache_ttl_seconds=CacheTTL.RELEASE_HISTORY,
    )


@router.get("/projects/{project_id}/update-frequency", responses=RESP_AUTH_404)
async def get_project_update_frequency(
    project_id: str,
    request: Request,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    max_scans: Annotated[int, Query(ge=2, le=500)] = 20,
    window_days: Annotated[int | None, Query(ge=1, le=3650)] = None,
    branch: Annotated[str | None, Query(max_length=512)] = None,
) -> UpdateFrequencyMetrics:
    """Update-frequency metrics from version diffs; window_days scopes by time, else max_scans.

    The timeline covers one branch (``branch`` if given, else the newest
    scanned live branch) so cross-branch differences are not counted as updates.
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    project_repo = ProjectRepository(db)
    project = await project_repo.get_raw_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    user_project_ids = await get_user_project_ids(current_user, db)
    if project_id not in user_project_ids:
        raise HTTPException(status_code=403, detail=_MSG_ACCESS_DENIED)

    version_token = await _project_scan_version(db, project_id)
    cache_key = _project_cache_key(
        project_id, max_scans=max_scans, window_days=window_days, branch=branch, version_token=version_token
    )
    cached = await cache_service.get(cache_key)
    if cached:
        return UpdateFrequencyMetrics(**cached)

    scan_repo = ScanRepository(db)
    dep_repo = DependencyRepository(db)
    analysis_repo = AnalysisResultRepository(db)

    metrics = await _await_or_abort(
        request,
        compute_update_frequency(
            project_id=project_id,
            project_name=project.get("name", "Unknown"),
            scan_repo=scan_repo,
            dep_repo=dep_repo,
            analysis_repo=analysis_repo,
            max_scans=max_scans,
            since=_resolve_since(window_days),
            release_fetcher=_build_release_fetcher(),
            branch=branch,
            deleted_branches=project.get("deleted_branches"),
            default_branch=project.get("default_branch"),
        ),
    )

    await cache_service.set(cache_key, metrics.model_dump(), ttl_seconds=CacheTTL.UPDATE_FREQUENCY)
    return metrics


async def _compute_comparison(
    db: DatabaseDep,
    user_project_ids: list[str],
    team_id: str | None,
    *,
    max_scans: int,
    window_days: int | None,
) -> dict[str, Any]:
    query: dict[str, Any] = {"_id": {"$in": user_project_ids}}
    if team_id:
        query["team_id"] = team_id

    project_repo = ProjectRepository(db)
    projects_raw = await project_repo.find_many_raw(
        query,
        projection={"_id": 1, "name": 1, "team_id": 1, "deleted_branches": 1, "default_branch": 1},
        limit=len(user_project_ids),
    )

    unique_team_ids = list({str(p["team_id"]) for p in projects_raw if p.get("team_id")})
    team_names: dict[str, str] = {}
    if unique_team_ids:
        cursor = db.teams.find(
            {"_id": {"$in": unique_team_ids}},
            {"_id": 1, "name": 1},
        )
        async for t in cursor:
            team_names[str(t["_id"])] = t.get("name", "")

    for p in projects_raw:
        p["team_name"] = team_names.get(p.get("team_id", ""))

    # No release-history fetcher: comparison only needs team-velocity fields, and
    # per-package deps.dev round-trips per project would dominate latency.
    comparison = await compute_update_frequency_comparison(
        projects=projects_raw,
        scan_repo=ScanRepository(db),
        dep_repo=DependencyRepository(db),
        analysis_repo=AnalysisResultRepository(db),
        max_scans=max_scans,
        since=_resolve_since(window_days),
    )
    return comparison.model_dump()


@router.get("/update-frequency/comparison", responses=RESP_AUTH)
async def get_update_frequency_comparison(
    request: Request,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    team_id: str | None = None,
    max_scans: Annotated[int, Query(ge=2, le=200)] = 20,
    window_days: Annotated[int | None, Query(ge=1, le=3650)] = None,
) -> UpdateFrequencyComparison:
    """Cross-project ranking. Pass ``window_days`` to align scan cadences."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    user_project_ids = await get_user_project_ids(current_user, db)

    if not user_project_ids:
        return UpdateFrequencyComparison(
            projects=[],
            team_avg_updates_per_month=0.0,
            team_avg_coverage_pct=None,
        )

    cache_key = _comparison_cache_key(
        _scope_hash(user_project_ids),
        team_id or "all",
        max_scans=max_scans,
        window_days=window_days,
    )

    payload = await _await_or_abort(
        request,
        cache_service.get_or_fetch_with_lock(
            cache_key,
            lambda: _compute_comparison(
                db, user_project_ids, team_id, max_scans=max_scans, window_days=window_days
            ),
            ttl_seconds=CacheTTL.UPDATE_FREQUENCY,
            lock_ttl_seconds=_COMPARISON_LOCK_TTL_SECONDS,
            max_wait_seconds=_COMPARISON_LOCK_WAIT_SECONDS,
            reraise_fetch_errors=True,
        ),
    )
    if not payload:
        raise HTTPException(status_code=503, detail="Update-frequency comparison is temporarily unavailable")
    return UpdateFrequencyComparison(**payload)
