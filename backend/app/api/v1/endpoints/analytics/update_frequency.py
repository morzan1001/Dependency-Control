"""Analytics update-frequency endpoints."""

import asyncio
import contextlib
import logging
from collections import Counter
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Annotated, Any, cast

import httpx
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
from app.core.constants import SLOWEST_PACKAGES_LIMIT
from app.core.http_utils import InstrumentedAsyncClient
from app.core.permissions import Permissions
from app.models.project import Project
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import USABLE_BUILD_MATCH, ScanRepository
from app.repositories.update_frequency import (
    WINDOW_HARD_LIMIT,
    BranchWindowActivity,
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
    window_scans_by_branch,
)
from app.schemas.analytics import (
    ProjectUpdateSummary,
    SlowPackage,
    UpdateDataStatus,
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
    load_scan_deps,
    load_outdated_entries,
    rank_summaries,
    select_primary_branch,
    window_cutoff,
)
from app.services.update_frequency_fold import (
    commit_coverage,
    fold_window,
    select_window,
    window_bars,
)

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_DISCONNECT_POLL_SECONDS = 1.0

# Ranking projects without a shared window compares different time spans, so the
# comparison always fixes one; a quarter covers the slowest realistic scan cadence.
_DEFAULT_COMPARISON_WINDOW_DAYS = 90

# Worst-case wall time of one comparison recompute over the largest tenant. The live
# path walks every scan of every visible project; the rollup path reads a handful of
# bounded queries and folds them in memory, so it needs a fraction of the room.
_LIVE_COMPARISON_BUDGET_SECONDS = 240.0
_ROLLUP_COMPARISON_BUDGET_SECONDS = 30.0


def _lock_timings(use_rollup: bool) -> tuple[float, int]:
    """Waiter and lock lifetimes for the path that is about to run.

    A waiter must outlast the recompute or it starts a duplicate one; the lock
    must outlast the waiter, or a second caller recomputes under the holder.
    """
    budget = _ROLLUP_COMPARISON_BUDGET_SECONDS if use_rollup else _LIVE_COMPARISON_BUDGET_SECONDS
    return budget, int(budget) + 60


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
    use_rollup: bool,
) -> str:
    """Cache key versioned by the analysed branch's scans, so a scan finishing there misses the cache."""
    branch_tag = "b" if branch is None else f"b={branch}"
    return (
        f"{CacheKeys.update_frequency(project_id)}"
        f":m{max_scans}:w{window_days or 0}:{branch_tag}:r{int(use_rollup)}:v{version_token}"
    )


def _comparison_cache_key(
    scope_hash: str,
    team_id: str | None,
    *,
    window_days: int,
    use_rollup: bool,
) -> str:
    """Cache key shared by every caller with the same visible-project scope.

    The read path is part of the key: only the rollup can tell that the ledger
    is behind, so the two disagree on ``data_status`` while it is, and flipping
    the flag must not serve the other path's entry for the rest of its TTL.
    """
    base = CacheKeys.update_frequency_comparison(scope_hash, team_id)
    return f"{base}:w{window_days}:r{int(use_rollup)}"


async def _branch_scan_token(db: DatabaseDep, project_id: str, branch: str | None, since: datetime | None) -> str:
    """Count and newest completion of the scans the walk reads; the latter catches a re-finalised scan."""
    match: dict[str, Any] = {**USABLE_BUILD_MATCH, "project_id": project_id, "branch": branch}
    if since is not None:
        match["created_at"] = {"$gte": since}
    rows = await ScanRepository(db).aggregate(
        [{"$match": match}, {"$group": {"_id": None, "scans": {"$sum": 1}, "completed_at": {"$max": "$completed_at"}}}]
    )
    return f"{rows[0]['scans']}@{rows[0]['completed_at']}" if rows else "0"


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
    branch: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
) -> UpdateFrequencyMetrics:
    """Update-frequency metrics from version diffs; window_days scopes by time, else max_scans.

    The timeline covers one branch (``branch`` if given, else the newest
    scanned live branch) so cross-branch differences are not counted as updates.
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)
    project = await check_project_access(project_id, current_user, db)

    # The rollup covers exactly the default view; an explicit branch or the
    # max_scans mode still needs the live walk over the scan history.
    rollup_window_days = window_days if settings.UPDATE_FREQUENCY_USE_ROLLUP and branch is None else None

    since = window_cutoff(window_days)
    analyzed_branch = branch
    if analyzed_branch is None:
        activity = await window_scans_by_branch(ScanRepository(db), [project_id], since)
        by_branch = {seen_branch: seen for (_project_id, seen_branch), seen in activity.items()}
        analyzed_branch = select_primary_branch(by_branch, project.default_branch, project.deleted_branches)
    cache_key = _project_cache_key(
        project_id,
        max_scans=max_scans,
        window_days=window_days,
        branch=analyzed_branch,
        version_token=await _branch_scan_token(db, project_id, analyzed_branch, since),
        use_rollup=rollup_window_days is not None,
    )

    async def _fetch() -> dict[str, Any]:
        metrics = None
        if rollup_window_days is not None:
            metrics = await _rollup_project_metrics(db, project, rollup_window_days)
        if metrics is None:
            metrics = await compute_update_frequency(
                project_id=project_id,
                project_name=project.name,
                scan_repo=ScanRepository(db),
                dep_repo=DependencyRepository(db),
                analysis_repo=AnalysisResultRepository(db),
                max_scans=max_scans,
                window_days=window_days,
                release_fetcher=_build_release_fetcher(),
                branch=analyzed_branch,
                deleted_branches=project.deleted_branches,
                default_branch=project.default_branch,
            )
        return metrics.model_dump()

    # A rollup miss falls back to the live walk, so the lock is sized for the walk.
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
    """The caller's visible projects, each carrying every team that owns it.

    ``team_id`` narrows to one team's holding, co-owned projects included, so a project appears in
    each of its owners' comparisons in full. The per-team rankings therefore overlap, and the rows
    across all of them outnumber the estate's projects.
    """
    query: dict[str, Any] = {"_id": {"$in": user_project_ids}}
    if team_id:
        query["team_ids"] = team_id

    projects_raw = await ProjectRepository(db).find_many_raw(
        query,
        sort_by="name",
        projection={"_id": 1, "name": 1, "team_ids": 1, "deleted_branches": 1, "default_branch": 1},
        limit=len(user_project_ids),
    )

    team_names = await resolve_team_names(db, {tid for p in projects_raw for tid in p.get("team_ids") or []})
    for p in projects_raw:
        p["teams"] = team_refs(p.get("team_ids") or [], team_names)
    return projects_raw


async def _compute_comparison(
    db: DatabaseDep,
    user_project_ids: list[str],
    team_id: str | None,
    *,
    window_days: int,
) -> dict[str, Any]:
    projects_raw = await _scoped_projects(db, user_project_ids, team_id)

    # No release-history fetcher: comparison only needs team-velocity fields, and
    # per-package deps.dev round-trips per project would dominate latency.
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
    """Which branch of a project the delta ledger could fold, and how far it got."""

    branch: str | None
    window: list[dict[str, Any]]
    status: UpdateDataStatus
    # Set only when the cap truncated the branch: the rate then has to divide by the
    # stretch actually read, not by a window whose older part was never looked at.
    measured_days: int | None = None
    bars: list[list[dict[str, Any]]] = field(default_factory=list)
    # Scans the fold covered when the branch holds more than the cap follows.
    window_scan_cap: int | None = None


def _resolve_window(
    activity: Mapping[str, BranchWindowActivity],
    deltas_by_branch: Mapping[str, list[dict[str, Any]]],
    project: dict[str, Any],
) -> _ResolvedWindow:
    """The branch the scans elect, and how much of that branch's window the ledger can fold.

    The branch is chosen from the scans rather than from the deltas, so a ledger
    with holes cannot make this path report a different branch than the live one.
    """
    branch = select_primary_branch(activity, project.get("default_branch"), project.get("deleted_branches"))
    if branch is None:
        return _ResolvedWindow(None, [], "insufficient_data")
    return _fold_branch(branch, deltas_by_branch.get(branch, []), activity[branch])


def _fold_branch(branch: str, deltas: list[dict[str, Any]], activity: BranchWindowActivity) -> _ResolvedWindow:
    """How much of one branch's window the ledger can fold, and what that leaves out."""
    # The live walk stops at the same count of documents, so a branch busier than the
    # cap is truncated to the same newest stretch on both paths.
    capped = len(deltas) >= WINDOW_HARD_LIMIT
    deltas = deltas[-WINDOW_HARD_LIMIT:]
    if not deltas:
        return _ResolvedWindow(branch, [], "pending")

    window = select_window(deltas)
    bars = window_bars(window)
    if len(bars) < 2:
        # A writer failure is the reason there is nothing to fold, not a scan cadence.
        return _ResolvedWindow(branch, [], "error" if any(d.get("error") for d in deltas) else "insufficient_data")
    # Past the cap the branch's own commit count describes a longer stretch than either
    # path reads, so comparing against it would demote exactly the busiest projects.
    status: UpdateDataStatus = "ready" if capped else commit_coverage(deltas, window, activity.scans_per_commit).status
    measured_days = _spanned_days(bars) if capped else None
    return _ResolvedWindow(branch, window, status, measured_days, bars, WINDOW_HARD_LIMIT if capped else None)


def _spanned_days(bars: list[list[dict[str, Any]]]) -> int:
    """Whole days the folded stretch covers, floored at one so a burst cannot inflate a rate.

    Measured representative to representative, the two scans the bars are dated by.
    """
    span: timedelta = bars[-1][-1]["scan_created_at"] - bars[0][-1]["scan_created_at"]
    return max(1, round(span.total_seconds() / 86400))


def _rollup_summary(
    project: dict[str, Any],
    resolved: _ResolvedWindow,
    baselines: dict[str, set[str]],
    window_days: int,
) -> ProjectUpdateSummary:
    project_id = str(project["_id"])
    project_name = project.get("name", "")
    teams = project.get("teams") or []
    if resolved.status not in ("ready", "partial"):
        return ProjectUpdateSummary(
            project_id=project_id,
            project_name=project_name,
            teams=teams,
            data_status=resolved.status,
            branch=resolved.branch,
            window_days=window_days,
        )

    anchor_id = resolved.window[0]["_id"]
    folded = fold_window(resolved.window, baselines.get(anchor_id), resolved.measured_days or window_days)
    return folded.to_summary(
        project_id,
        project_name,
        teams,
        branch=resolved.branch,
        window_days=window_days,
        data_status=resolved.status,
        window_scan_cap=resolved.window_scan_cap,
    )


async def _compute_comparison_from_rollup(
    db: DatabaseDep,
    user_project_ids: list[str],
    team_id: str | None,
    *,
    window_days: int,
) -> dict[str, Any]:
    """Comparison folded from the delta ledger: a handful of bounded queries, no per-scan walk."""
    projects_raw = await _scoped_projects(db, user_project_ids, team_id)
    if not projects_raw:
        return UpdateFrequencyComparison(projects=[]).model_dump()

    since = cast(datetime, window_cutoff(window_days))
    project_ids = [str(p["_id"]) for p in projects_raw]
    activity = await window_scans_by_branch(ScanRepository(db), project_ids, since)
    buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch(project_ids, since)

    scans_by_project: dict[str, dict[str, BranchWindowActivity]] = {}
    for (project_id, branch), seen in activity.items():
        scans_by_project.setdefault(project_id, {})[branch] = seen
    deltas_by_project: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for (project_id, branch), deltas in buckets.items():
        deltas_by_project.setdefault(project_id, {})[branch] = deltas

    resolved = {
        project_id: _resolve_window(
            scans_by_project.get(project_id, {}), deltas_by_project.get(project_id, {}), project
        )
        for project_id, project in zip(project_ids, projects_raw, strict=True)
    }

    baselines = await ScanOutdatedSetRepository(db).names_by_scan(
        [r.window[0]["_id"] for r in resolved.values() if r.window]
    )

    summaries = [_rollup_summary(p, resolved[str(p["_id"])], baselines, window_days) for p in projects_raw]
    return rank_summaries(summaries).model_dump()


async def _rollup_slowest_packages(
    db: DatabaseDep, bars: Sequence[Sequence[dict[str, Any]]]
) -> tuple[list[SlowPackage], int]:
    """The table's rows, ranked by how many timeline bars kept flagging the package, and its backlog."""
    scan_ids = [bar[-1]["_id"] for bar in bars]
    outdated_sets = await ScanOutdatedSetRepository(db).names_by_scan(scan_ids)
    latest_id = next((scan_id for scan_id in reversed(scan_ids) if scan_id in outdated_sets), None)
    if latest_id is None:
        return [], 0

    # Resolved packages are history, not backlog.
    remaining = outdated_sets[latest_id]
    counts = Counter(name for names in outdated_sets.values() for name in names if name in remaining)

    entries = await load_outdated_entries(AnalysisResultRepository(db), latest_id) or []
    analyzer_info = {component: e for e in entries if (component := e.get("component"))}
    deps = await load_scan_deps(DependencyRepository(db), latest_id)
    types = {info["name"]: info["type"] for info in deps.values()}
    # current_version describes what the project holds now, so it comes from the newest bar
    # even when the backlog was last measured on an older one.
    newest_deps = deps if scan_ids[-1] == latest_id else await load_scan_deps(DependencyRepository(db), scan_ids[-1])
    # An ambiguous bare name would show one purl sibling's version for the other.
    per_name = Counter(info["name"] for info in newest_deps.values())
    versions = {info["name"]: info["version"] for info in newest_deps.values() if per_name[info["name"]] == 1}

    return [
        SlowPackage(
            name=name,
            type=types.get(name, "unknown"),
            current_version=versions.get(name) or analyzer_info.get(name, {}).get("current_version"),
            latest_version=analyzer_info.get(name, {}).get("latest_version"),
            scans_outdated=count,
        )
        for name, count in sorted(counts.items(), key=lambda entry: (-entry[1], entry[0]))[:SLOWEST_PACKAGES_LIMIT]
    ], len(counts)


async def _rollup_project_metrics(db: DatabaseDep, project: Project, window_days: int) -> UpdateFrequencyMetrics | None:
    """Metrics folded from the delta ledger, or None when it cannot answer for this project.

    A partial fold falls back to the live walk rather than being served: one
    project's walk is affordable, and it reads the scans the ledger has not
    reached yet.
    """
    project_id = project.id
    since = cast(datetime, window_cutoff(window_days))
    activity = await window_scans_by_branch(ScanRepository(db), [project_id], since)
    by_branch = {branch: seen for (_project_id, branch), seen in activity.items()}
    branch = select_primary_branch(by_branch, project.default_branch, project.deleted_branches)
    if branch is None:
        return None

    deltas = await ScanUpdateDeltaRepository(db).find_project_window(project_id, branch, since, WINDOW_HARD_LIMIT)
    resolved = _fold_branch(branch, deltas, by_branch[branch])
    if resolved.status != "ready":
        return None

    anchor_id = resolved.window[0]["_id"]
    baselines = await ScanOutdatedSetRepository(db).names_by_scan([anchor_id])
    folded = fold_window(resolved.window, baselines.get(anchor_id), resolved.measured_days or window_days)
    slowest_packages, outdated_backlog = await _rollup_slowest_packages(db, resolved.bars)
    return folded.to_metrics(
        project_id,
        project.name,
        branch=resolved.branch,
        slowest_packages=slowest_packages,
        window_scan_cap=resolved.window_scan_cap,
        outdated_backlog=outdated_backlog,
    )


@router.get("/update-frequency/comparison", responses=RESP_AUTH)
async def get_update_frequency_comparison(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    team_id: str | None = None,
    window_days: Annotated[int, Query(ge=1, le=3650)] = _DEFAULT_COMPARISON_WINDOW_DAYS,
) -> UpdateFrequencyComparison:
    """Cross-project ranking over one calendar window, so scan cadences stay comparable.

    There is no scan-count mode here: a shared calendar window is what makes the
    projects comparable, and it selects the scans on both read paths.
    """
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
