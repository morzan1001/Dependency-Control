import asyncio
import contextlib
from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, cast

from fastapi import HTTPException, Query, Request

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.api.v1.helpers.teams import resolve_team_names, team_refs
from app.core.cache import CacheKeys, CacheTTL, cache_service, scope_digest
from app.core.config import settings
from app.core.constants import SCANS_TIP_SORT
from app.core.permissions import Permissions
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.update_frequency import (
    WINDOW_HARD_LIMIT,
    BranchWindowActivity,
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
    usable_scan_match,
    window_scans_by_branch,
)
from app.schemas.analytics import (
    ProjectUpdateSummary,
    UpdateDataStatus,
    UpdateFrequencyComparison,
    UpdateFrequencyMetrics,
)
from app.services.release_history import DepsDevReleaseHistoryFetcher
from app.services.update_frequency import (
    compute_update_frequency,
    compute_update_frequency_comparison,
    elect_primary_branch,
    measured_summary,
    placeholder_summary,
    rank_summaries,
    retained_window,
    retention_horizon,
    select_primary_branch,
    spanned_days,
    walk_fetch_limit,
    window_cutoff,
)
from app.services.update_frequency_fold import (
    commit_coverage,
    fold_window,
    select_window,
    window_bars,
)

router = CustomAPIRouter()

_DISCONNECT_POLL_SECONDS = 1.0

# A ranking needs one shared window to compare like spans; a quarter covers the slowest realistic scan cadence.
_DEFAULT_COMPARISON_WINDOW_DAYS = 90

# Worst-case recompute times over the largest tenant: the live path walks every scan, the rollup a few queries.
_LIVE_COMPARISON_BUDGET_SECONDS = 240.0
_ROLLUP_COMPARISON_BUDGET_SECONDS = 30.0


def _lock_timings(use_rollup: bool) -> tuple[float, int]:
    """The waiter outlasts the recompute and the lock the waiter, or a second caller starts a duplicate recompute."""
    budget = _ROLLUP_COMPARISON_BUDGET_SECONDS if use_rollup else _LIVE_COMPARISON_BUDGET_SECONDS
    return budget, int(budget) + 60


async def _await_or_abort[T](request: Request, coro: Coroutine[Any, Any, T]) -> T:
    task = asyncio.ensure_future(coro)
    try:
        while True:
            done, _pending = await asyncio.wait({task}, timeout=_DISCONNECT_POLL_SECONDS)
            if done:
                return task.result()
            if await request.is_disconnected():
                raise HTTPException(status_code=499, detail="Client disconnected")
    finally:
        # asyncio.wait() leaves its futures running, so the task outlives any exit, shutdown included, unless killed.
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
    """Cache key versioned by the analysed branch's scans, so a scan finishing there misses the cache."""
    branch_tag = "b" if branch is None else f"b={branch}"
    return f"{CacheKeys.update_frequency(project_id)}:m{max_scans}:w{window_days or 0}:{branch_tag}:v{version_token}"


def _comparison_cache_key(
    scope_hash: str,
    team_id: str | None,
    *,
    window_days: int,
    use_rollup: bool,
) -> str:
    """The read path is in the key: only the rollup sees a lagging ledger, so the paths disagree on data_status."""
    base = CacheKeys.update_frequency_comparison(scope_hash, team_id)
    return f"{base}:w{window_days}:r{int(use_rollup)}"


async def _branch_scan_token(
    db: DatabaseDep, project_id: str, branch: str | None, since: datetime | None, limit: int
) -> str:
    """Count, newest completion and oldest date of the scans the walk reads: a re-finalised or retired one moves it."""
    match = {**usable_scan_match(since), "project_id": project_id, "branch": branch}
    rows = await ScanRepository(db).aggregate(
        [
            {"$match": match},
            # The tip order is indexed, so the read stops at the walk's stretch instead of grouping the branch.
            {"$sort": dict(SCANS_TIP_SORT)},
            {"$limit": limit},
            {
                "$group": {
                    "_id": None,
                    "scans": {"$sum": 1},
                    "completed_at": {"$max": "$completed_at"},
                    "oldest": {"$min": "$created_at"},
                }
            },
        ]
    )
    return f"{rows[0]['scans']}@{rows[0]['completed_at']}@{rows[0]['oldest']}" if rows else "0"


@router.get("/projects/{project_id}/update-frequency", responses=RESP_AUTH_404)
async def get_project_update_frequency(
    project_id: str,
    request: Request,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    max_scans: Annotated[int, Query(ge=2, le=500)] = 20,
    window_days: Annotated[int | None, Query(ge=1, le=3650)] = None,
    branch: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
) -> UpdateFrequencyMetrics:
    """One branch's version-diff metrics, the newest live one by default; window_days scopes by time, else max_scans."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)
    project = await check_project_access(project_id, current_user, db)

    since = window_cutoff(window_days)
    analyzed_branch = branch or await elect_primary_branch(
        ScanRepository(db), project_id, since, project.default_branch, project.deleted_branches
    )
    cache_key = _project_cache_key(
        project_id,
        max_scans=max_scans,
        window_days=window_days,
        branch=analyzed_branch,
        version_token=await _branch_scan_token(
            db, project_id, analyzed_branch, since, walk_fetch_limit(max_scans, since)
        ),
    )

    async def _fetch() -> dict[str, Any]:
        system = await SystemSettingsRepository(db).get()
        metrics = await compute_update_frequency(
            project_id=project_id,
            project_name=project.name,
            scan_repo=ScanRepository(db),
            dep_repo=DependencyRepository(db),
            analysis_repo=AnalysisResultRepository(db),
            max_scans=max_scans,
            window_days=window_days,
            release_fetcher=DepsDevReleaseHistoryFetcher(),
            branch=analyzed_branch,
            retention_days=retention_horizon(system, project.retention_days, project.retention_action),
        )
        return metrics.model_dump()

    lock_wait_seconds, lock_ttl_seconds = _lock_timings(use_rollup=False)
    payload = await _await_or_abort(
        request,
        cache_service.get_or_fetch_with_lock(
            cache_key,
            _fetch,
            ttl_seconds=CacheTTL.UPDATE_FREQUENCY,
            lock_ttl_seconds=lock_ttl_seconds,
            max_wait_seconds=lock_wait_seconds,
            reraise_fetch_errors=True,
        ),
    )
    return UpdateFrequencyMetrics.model_validate(payload)


async def _scoped_projects(
    db: DatabaseDep,
    user_project_ids: list[str],
    team_id: str | None,
) -> list[dict[str, Any]]:
    """``team_id`` keeps co-owned projects, so per-team rankings overlap and together outnumber the estate."""
    query: dict[str, Any] = {"_id": {"$in": user_project_ids}}
    if team_id:
        query["team_ids"] = team_id

    projects_raw = await ProjectRepository(db).find_many_raw(
        query,
        sort_by="name",
        projection={
            "_id": 1,
            "name": 1,
            "team_ids": 1,
            "deleted_branches": 1,
            "default_branch": 1,
            "retention_days": 1,
            "retention_action": 1,
        },
        limit=len(user_project_ids),
    )

    team_names = await resolve_team_names(db, {tid for p in projects_raw for tid in p.get("team_ids") or []})
    system = await SystemSettingsRepository(db).get()
    for p in projects_raw:
        p["teams"] = team_refs(p.get("team_ids") or [], team_names)
        p["retention_horizon"] = retention_horizon(system, p.get("retention_days"), p.get("retention_action"))
    return projects_raw


async def _compute_comparison(
    db: DatabaseDep,
    user_project_ids: list[str],
    team_id: str | None,
    *,
    window_days: int,
) -> dict[str, Any]:
    projects_raw = await _scoped_projects(db, user_project_ids, team_id)

    # No release-history fetcher: the comparison needs only velocity fields, and deps.dev round-trips would dominate.
    comparison = await compute_update_frequency_comparison(
        projects=projects_raw,
        scan_repo=ScanRepository(db),
        dep_repo=DependencyRepository(db),
        analysis_repo=AnalysisResultRepository(db),
        window_days=window_days,
    )
    return comparison.model_dump()


@dataclass(frozen=True)
class _ResolvedWindow:
    branch: str | None
    window: list[dict[str, Any]]
    status: UpdateDataStatus
    # Set only when the cap truncated the branch, so the rate divides by the stretch actually read.
    measured_days: int | None = None
    window_scan_cap: int | None = None


async def _resolve_windows(
    db: DatabaseDep, projects: list[dict[str, Any]], since: datetime
) -> dict[str, _ResolvedWindow]:
    """The scans pick the branch before any delta is read, so a ledger with holes cannot pick another one than live."""
    project_ids = [str(p["_id"]) for p in projects]
    activity = await window_scans_by_branch(ScanRepository(db), project_ids, since)
    primaries = {
        project_id: select_primary_branch(
            activity.get(project_id, {}), project.get("default_branch"), project.get("deleted_branches")
        )
        for project_id, project in zip(project_ids, projects, strict=True)
    }
    # The live walk stops at the same count, so both paths truncate a branch busier than the cap to the same stretch.
    chains = await ScanUpdateDeltaRepository(db).window_chains(
        [(project_id, branch) for project_id, branch in primaries.items() if branch is not None],
        since,
        WINDOW_HARD_LIMIT,
    )
    return {
        project_id: (
            _ResolvedWindow(None, [], "insufficient_data")
            if branch is None
            else _fold_branch(branch, chains[project_id, branch], activity[project_id][branch])
        )
        for project_id, branch in primaries.items()
    }


def _fold_branch(branch: str, deltas: list[dict[str, Any]], activity: BranchWindowActivity) -> _ResolvedWindow:
    capped = len(deltas) >= WINDOW_HARD_LIMIT
    if not deltas:
        return _ResolvedWindow(branch, [], "pending")

    window = select_window(deltas)
    bars = window_bars(window)
    if len(bars) < 2:
        # A writer failure is the reason there is nothing to fold, not a scan cadence.
        return _ResolvedWindow(branch, [], "error" if any(d.get("error") for d in deltas) else "insufficient_data")
    # Past the cap the commit count spans more than either path reads, so comparing to it demotes the busiest projects.
    status: UpdateDataStatus = "ready" if capped else commit_coverage(deltas, window, activity.scans_per_commit).status
    # Measured representative to representative, the two scans the bars are dated by.
    measured_days = spanned_days(bars[0][-1]["scan_created_at"], bars[-1][-1]["scan_created_at"]) if capped else None
    return _ResolvedWindow(branch, window, status, measured_days, WINDOW_HARD_LIMIT if capped else None)


def _rollup_summary(
    project: dict[str, Any],
    resolved: _ResolvedWindow,
    baselines: dict[str, set[str]],
    window_days: int,
) -> ProjectUpdateSummary:
    if resolved.status not in ("ready", "partial"):
        return placeholder_summary(project, resolved.status, window_days, resolved.branch)

    anchor_id = resolved.window[0]["_id"]
    retained = None if resolved.measured_days else retained_window(window_days, project.get("retention_horizon"))
    rate_days = resolved.measured_days or retained or window_days
    folded = fold_window(resolved.window, baselines.get(anchor_id), rate_days)
    metrics = folded.to_metrics(
        str(project["_id"]),
        project.get("name", ""),
        branch=resolved.branch,
        window_scan_cap=resolved.window_scan_cap,
        retention_days=retained,
    )
    return measured_summary(metrics, project.get("teams") or [], window_days=window_days, data_status=resolved.status)


async def _compute_comparison_from_rollup(
    db: DatabaseDep,
    user_project_ids: list[str],
    team_id: str | None,
    *,
    window_days: int,
) -> dict[str, Any]:
    projects_raw = await _scoped_projects(db, user_project_ids, team_id)
    if not projects_raw:
        return UpdateFrequencyComparison(projects=[]).model_dump()

    resolved = await _resolve_windows(db, projects_raw, cast(datetime, window_cutoff(window_days)))

    baselines = await ScanOutdatedSetRepository(db).names_by_scan(
        [r.window[0]["_id"] for r in resolved.values() if r.window]
    )

    summaries = [_rollup_summary(p, resolved[str(p["_id"])], baselines, window_days) for p in projects_raw]
    return rank_summaries(summaries).model_dump()


@router.get("/update-frequency/comparison", responses=RESP_AUTH)
async def get_update_frequency_comparison(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    team_id: str | None = None,
    window_days: Annotated[int, Query(ge=1, le=3650)] = _DEFAULT_COMPARISON_WINDOW_DAYS,
) -> UpdateFrequencyComparison:
    """Cross-project ranking over one calendar window, never a scan count, so scan cadences stay comparable."""
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    user_project_ids = await get_user_project_ids(current_user, db)

    if not user_project_ids:
        return UpdateFrequencyComparison(projects=[])

    use_rollup = settings.UPDATE_FREQUENCY_USE_ROLLUP
    scope = scope_digest(user_project_ids)
    if team_id:
        # A row does not depend on the filter, so a cached estate ranking answers any team in it.
        everyone = await cache_service.get(
            _comparison_cache_key(scope, None, window_days=window_days, use_rollup=use_rollup)
        )
        if everyone is not None:
            team_project_ids = {str(p["_id"]) for p in await _scoped_projects(db, user_project_ids, team_id)}
            return rank_summaries(
                [ProjectUpdateSummary(**row) for row in everyone["projects"] if row["project_id"] in team_project_ids]
            )

    compute = _compute_comparison_from_rollup if use_rollup else _compute_comparison
    lock_wait_seconds, lock_ttl_seconds = _lock_timings(use_rollup)
    # Not tied to the caller's connection: other requests wait on this fetch to publish.
    payload = await cache_service.get_or_fetch_with_lock(
        _comparison_cache_key(scope, team_id, window_days=window_days, use_rollup=use_rollup),
        lambda: compute(db, user_project_ids, team_id, window_days=window_days),
        ttl_seconds=CacheTTL.UPDATE_FREQUENCY,
        lock_ttl_seconds=lock_ttl_seconds,
        max_wait_seconds=lock_wait_seconds,
        reraise_fetch_errors=True,
    )
    return UpdateFrequencyComparison.model_validate(payload)
