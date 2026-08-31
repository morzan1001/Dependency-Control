"""Analytics update-frequency endpoints."""

import asyncio
import contextlib
import hashlib
import logging
from collections import Counter
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, cast

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
from app.core.config import settings
from app.core.constants import SCAN_USABLE_STATUSES
from app.core.http_utils import InstrumentedAsyncClient
from app.core.permissions import Permissions
from app.repositories import (
    AnalysisResultRepository,
    DependencyRepository,
    ProjectRepository,
    ScanRepository,
)
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
    DEP_PROJECTION,
    as_utc,
    compute_update_frequency,
    compute_update_frequency_comparison,
    fold_scan_deps,
    load_outdated_entries,
    rank_summaries,
    select_primary_branch,
    window_coverage_status,
    window_cutoff,
)
from app.services.update_frequency_fold import (
    accounted_commits,
    fold_window,
    select_window,
    window_bars,
)

from ._shared import _MSG_ACCESS_DENIED

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

_SLOWEST_PACKAGES_LIMIT = 15


def _comparison_lock_timings(use_rollup: bool) -> tuple[float, int]:
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
    """Cache key carrying a completion-monotonic token so a finished scan misses the cache."""
    return (
        f"{CacheKeys.update_frequency(project_id)}"
        f":m{max_scans}:w{window_days or 0}:b{branch or 'auto'}:r{int(use_rollup)}:v{version_token}"
    )


def _scope_hash(project_ids: list[str]) -> str:
    """Digest of the caller's visible projects: the authorization boundary, shared by equal scopes."""
    return hashlib.md5(",".join(sorted(project_ids)).encode(), usedforsecurity=False).hexdigest()[:16]


def _comparison_cache_key(
    scope_hash: str,
    team_id: str,
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

    # The rollup covers exactly the default view; an explicit branch or the
    # max_scans mode still needs the live walk over the scan history.
    rollup_window_days = window_days if settings.UPDATE_FREQUENCY_USE_ROLLUP and branch is None else None

    version_token = await _project_scan_version(db, project_id)
    cache_key = _project_cache_key(
        project_id,
        max_scans=max_scans,
        window_days=window_days,
        branch=branch,
        version_token=version_token,
        use_rollup=rollup_window_days is not None,
    )
    cached = await cache_service.get(cache_key)
    if cached:
        return UpdateFrequencyMetrics(**cached)

    metrics = None
    if rollup_window_days is not None:
        metrics = await _await_or_abort(request, _rollup_project_metrics(db, project, rollup_window_days))

    if metrics is None:
        metrics = await _await_or_abort(
            request,
            compute_update_frequency(
                project_id=project_id,
                project_name=project.get("name", "Unknown"),
                scan_repo=ScanRepository(db),
                dep_repo=DependencyRepository(db),
                analysis_repo=AnalysisResultRepository(db),
                max_scans=max_scans,
                window_days=window_days,
                release_fetcher=_build_release_fetcher(),
                branch=branch,
                deleted_branches=project.get("deleted_branches"),
                default_branch=project.get("default_branch"),
            ),
        )

    await cache_service.set(cache_key, metrics.model_dump(), ttl_seconds=CacheTTL.UPDATE_FREQUENCY)
    return metrics


async def _scoped_projects(
    db: DatabaseDep,
    user_project_ids: list[str],
    team_id: str | None,
) -> list[dict[str, Any]]:
    """The caller's visible projects, each carrying its team name."""
    query: dict[str, Any] = {"_id": {"$in": user_project_ids}}
    if team_id:
        query["team_id"] = team_id

    projects_raw = await ProjectRepository(db).find_many_raw(
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
    status: UpdateDataStatus = (
        "ready" if capped else window_coverage_status(accounted_commits(deltas, window), activity.commit_count)
    )
    measured_days = _spanned_days(bars) if capped else None
    return _ResolvedWindow(branch, window, status, measured_days, bars)


def _spanned_days(bars: list[list[dict[str, Any]]]) -> int:
    """Whole days the folded stretch covers, floored at one so a burst cannot inflate a rate.

    Measured representative to representative, the two scans the bars are dated by.
    """
    span = as_utc(bars[-1][-1]["scan_created_at"]) - as_utc(bars[0][-1]["scan_created_at"])
    return max(1, round(span.total_seconds() / 86400))


def _rollup_summary(
    project: dict[str, Any],
    resolved: _ResolvedWindow,
    baselines: dict[str, set[str]],
    window_days: int,
) -> ProjectUpdateSummary:
    project_id = str(project["_id"])
    project_name = project.get("name", "")
    team_name = project.get("team_name")
    if resolved.status not in ("ready", "partial"):
        return ProjectUpdateSummary(
            project_id=project_id,
            project_name=project_name,
            team_name=team_name,
            data_status=resolved.status,
            branch=resolved.branch,
            window_days=window_days,
        )

    anchor_id = resolved.window[0]["_id"]
    folded = fold_window(resolved.window, baselines.get(anchor_id), resolved.measured_days or window_days)
    return folded.to_summary(
        project_id,
        project_name,
        team_name,
        branch=resolved.branch,
        window_days=window_days,
        data_status=resolved.status,
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


async def _scan_deps(db: DatabaseDep, scan_id: str) -> dict[str, dict[str, str]]:
    return fold_scan_deps(await DependencyRepository(db).find_all({"scan_id": scan_id}, projection=DEP_PROJECTION))


async def _rollup_slowest_packages(db: DatabaseDep, bars: Sequence[Sequence[dict[str, Any]]]) -> list[SlowPackage]:
    """Remaining backlog, ranked by how many timeline bars kept flagging the package."""
    scan_ids = [bar[-1]["_id"] for bar in bars]
    outdated_sets = await ScanOutdatedSetRepository(db).names_by_scan(scan_ids)
    latest_id = next((scan_id for scan_id in reversed(scan_ids) if scan_id in outdated_sets), None)
    if latest_id is None:
        return []

    # Resolved packages are history, not backlog.
    remaining = outdated_sets[latest_id]
    counts = Counter(name for names in outdated_sets.values() for name in names if name in remaining)

    entries = await load_outdated_entries(AnalysisResultRepository(db), latest_id) or []
    analyzer_info = {component: e for e in entries if (component := e.get("component"))}
    deps = await _scan_deps(db, latest_id)
    types = {info["name"]: info["type"] for info in deps.values()}
    # current_version describes what the project holds now, so it comes from the newest bar
    # even when the backlog was last measured on an older one.
    newest_deps = deps if scan_ids[-1] == latest_id else await _scan_deps(db, scan_ids[-1])
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
        for name, count in counts.most_common(_SLOWEST_PACKAGES_LIMIT)
    ]


async def _rollup_project_metrics(
    db: DatabaseDep, project: dict[str, Any], window_days: int
) -> UpdateFrequencyMetrics | None:
    """Metrics folded from the delta ledger, or None when it cannot answer for this project.

    A partial fold falls back to the live walk rather than being served: one
    project's walk is affordable, and it reads the scans the ledger has not
    reached yet.
    """
    project_id = str(project["_id"])
    since = cast(datetime, window_cutoff(window_days))
    activity = await window_scans_by_branch(ScanRepository(db), [project_id], since)
    by_branch = {branch: seen for (_project_id, branch), seen in activity.items()}
    branch = select_primary_branch(by_branch, project.get("default_branch"), project.get("deleted_branches"))
    if branch is None:
        return None

    deltas = await ScanUpdateDeltaRepository(db).find_project_window(project_id, branch, since, WINDOW_HARD_LIMIT)
    resolved = _fold_branch(branch, deltas, by_branch[branch])
    if resolved.status != "ready":
        return None

    anchor_id = resolved.window[0]["_id"]
    baselines = await ScanOutdatedSetRepository(db).names_by_scan([anchor_id])
    folded = fold_window(resolved.window, baselines.get(anchor_id), resolved.measured_days or window_days)
    return folded.to_metrics(
        project_id,
        project.get("name", "Unknown"),
        branch=resolved.branch,
        slowest_packages=await _rollup_slowest_packages(db, resolved.bars),
    )


@router.get("/update-frequency/comparison", responses=RESP_AUTH)
async def get_update_frequency_comparison(
    request: Request,
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
    cache_key = _comparison_cache_key(
        _scope_hash(user_project_ids),
        team_id or "all",
        window_days=window_days,
        use_rollup=use_rollup,
    )
    lock_wait_seconds, lock_ttl_seconds = _comparison_lock_timings(use_rollup)

    if use_rollup:

        def _fetch() -> Coroutine[Any, Any, dict[str, Any]]:
            return _compute_comparison_from_rollup(db, user_project_ids, team_id, window_days=window_days)
    else:

        def _fetch() -> Coroutine[Any, Any, dict[str, Any]]:
            return _compute_comparison(db, user_project_ids, team_id, window_days=window_days)

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
    if not payload:
        raise HTTPException(status_code=503, detail="Update-frequency comparison is temporarily unavailable")
    return UpdateFrequencyComparison(**payload)
