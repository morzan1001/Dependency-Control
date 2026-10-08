"""The ledger's fold of one project's window, read as the comparison reads it, for differentials against the walk."""

from typing import Any

from app.api.v1.endpoints.analytics.update_frequency import _resolve_window
from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
    window_scans_by_branch,
)
from app.schemas.analytics import UpdateFrequencyMetrics
from app.services.update_frequency import window_cutoff
from app.services.update_frequency_fold import fold_window


async def rollup_metrics(db: Any, project: dict[str, Any], window_days: int) -> UpdateFrequencyMetrics | None:
    """The folded window as full metrics, or None unless the comparison would rank the project as ready."""
    project_id = str(project["_id"])
    since = window_cutoff(window_days)
    assert since is not None
    activity = await window_scans_by_branch(ScanRepository(db), [project_id], since)
    buckets = await ScanUpdateDeltaRepository(db).group_window_by_branch([project_id], since)
    resolved = _resolve_window(activity.get(project_id, {}), buckets.get(project_id, {}), project)
    if resolved.status != "ready":
        return None
    anchor_id = resolved.window[0]["_id"]
    baselines = await ScanOutdatedSetRepository(db).names_by_scan([anchor_id])
    folded = fold_window(resolved.window, baselines.get(anchor_id), resolved.measured_days or window_days)
    return folded.to_metrics(
        project_id, project.get("name", ""), branch=resolved.branch, window_scan_cap=resolved.window_scan_cap
    )


def ledger_view(metrics: UpdateFrequencyMetrics) -> UpdateFrequencyMetrics:
    """The walk's metrics without what only the walk derives: slowest table, recent updates, dominant ecosystem."""
    return metrics.model_copy(
        update={"slowest_packages": [], "recent_updates": [], "outdated_backlog": 0, "dominant_ecosystem": None}
    )
