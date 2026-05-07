"""Analytics update-frequency endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Optional

from fastapi import HTTPException, Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import (
    get_user_project_ids,
    require_analytics_permission,
)
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_404
from app.core.cache import CacheKeys, CacheTTL, cache_service
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
from app.services.update_frequency import (
    compute_update_frequency,
    compute_update_frequency_comparison,
)

from ._shared import _MSG_ACCESS_DENIED

router = CustomAPIRouter()


def _resolve_since(window_days: Optional[int]) -> Optional[datetime]:
    """Translate the user-facing window_days param into a `since` cutoff."""
    if window_days is None:
        return None
    return datetime.now(tz=timezone.utc) - timedelta(days=window_days)


@router.get("/projects/{project_id}/update-frequency", responses=RESP_AUTH_404)
async def get_project_update_frequency(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    max_scans: Annotated[int, Query(ge=2, le=500)] = 20,
    window_days: Annotated[Optional[int], Query(ge=1, le=3650)] = None,
) -> UpdateFrequencyMetrics:
    """Update frequency metrics from comparing dependency versions across consecutive scans.

    Pass `window_days` (e.g. 365) to analyse all completed scans within that
    calendar window — recommended for cross-project comparability. Without it,
    the most recent `max_scans` completed scans are used.
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    project_repo = ProjectRepository(db)
    project = await project_repo.get_raw_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    user_project_ids = await get_user_project_ids(current_user, db)
    if project_id not in user_project_ids:
        raise HTTPException(status_code=403, detail=_MSG_ACCESS_DENIED)

    cache_key = f"{CacheKeys.update_frequency(project_id)}:m{max_scans}:w{window_days or 0}"
    cached = await cache_service.get(cache_key)
    if cached:
        return UpdateFrequencyMetrics(**cached)

    scan_repo = ScanRepository(db)
    dep_repo = DependencyRepository(db)
    analysis_repo = AnalysisResultRepository(db)

    metrics = await compute_update_frequency(
        project_id=project_id,
        project_name=project.get("name", "Unknown"),
        scan_repo=scan_repo,
        dep_repo=dep_repo,
        analysis_repo=analysis_repo,
        max_scans=max_scans,
        since=_resolve_since(window_days),
    )

    await cache_service.set(cache_key, metrics.model_dump(), ttl_seconds=CacheTTL.UPDATE_FREQUENCY)
    return metrics


@router.get("/update-frequency/comparison", responses=RESP_AUTH)
async def get_update_frequency_comparison(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    team_id: Optional[str] = None,
    max_scans: Annotated[int, Query(ge=2, le=200)] = 10,
    window_days: Annotated[Optional[int], Query(ge=1, le=3650)] = None,
) -> UpdateFrequencyComparison:
    """Ranking of projects by update behavior, optionally filtered by team.

    Pass `window_days` to align all projects on the same calendar window —
    recommended whenever scan cadences differ across projects.
    """
    require_analytics_permission(current_user, Permissions.ANALYTICS_RECOMMENDATIONS)

    cache_key = (
        f"{CacheKeys.update_frequency_comparison(current_user.id, team_id or 'all')}"
        f":m{max_scans}:w{window_days or 0}"
    )
    cached = await cache_service.get(cache_key)
    if cached:
        return UpdateFrequencyComparison(**cached)

    project_repo = ProjectRepository(db)
    user_project_ids = await get_user_project_ids(current_user, db)

    if not user_project_ids:
        return UpdateFrequencyComparison(
            projects=[],
            team_avg_updates_per_month=0.0,
            team_avg_coverage_pct=0.0,
        )

    query: Dict[str, Any] = {"_id": {"$in": user_project_ids}}
    if team_id:
        query["team_id"] = team_id

    projects_raw = await project_repo.find_many_raw(
        query,
        projection={"_id": 1, "name": 1, "team_id": 1},
        limit=len(user_project_ids),
    )

    if projects_raw:
        team_ids: List[str] = [str(p["team_id"]) for p in projects_raw if p.get("team_id")]
        unique_team_ids = list(set(team_ids))
        team_names: Dict[str, str] = {}
        if unique_team_ids:
            from app.repositories import TeamRepository

            team_repo = TeamRepository(db)
            for tid in unique_team_ids:
                team = await team_repo.get_raw_by_id(tid)
                if team:
                    team_names[tid] = team.get("name", "")

        for p in projects_raw:
            p["team_name"] = team_names.get(p.get("team_id", ""))

    scan_repo = ScanRepository(db)
    dep_repo = DependencyRepository(db)
    analysis_repo = AnalysisResultRepository(db)

    comparison = await compute_update_frequency_comparison(
        projects=projects_raw,
        scan_repo=scan_repo,
        dep_repo=dep_repo,
        analysis_repo=analysis_repo,
        max_scans=max_scans,
        since=_resolve_since(window_days),
    )

    await cache_service.set(cache_key, comparison.model_dump(), ttl_seconds=CacheTTL.UPDATE_FREQUENCY)
    return comparison
