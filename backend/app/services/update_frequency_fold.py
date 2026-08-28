"""Project-level update-frequency metrics folded from per-scan delta documents."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

from app.schemas.analytics import (
    DependencyUpdateEvent,
    ProjectUpdateSummary,
    ScanTimelineEntry,
    SlowPackage,
    UpdateFrequencyMetrics,
)
from app.services.release_history import UpstreamCadenceMetrics
from app.services.update_frequency import (
    ECOSYSTEM_DOMINANCE_THRESHOLD,
    as_utc,
    collapse_same_commit_runs,
    compute_trend,
    granularity_ratio,
    updates_per_month,
)

logger = logging.getLogger(__name__)

_UPDATE_KINDS = ("patch", "minor", "major", "unknown")
_RECENT_UPDATES_LIMIT = 30
_NOT_ENOUGH_SCANS = "Not enough scans to analyze (need at least 2)"


@dataclass(frozen=True)
class FoldedWindow:
    """Everything ``UpdateFrequencyMetrics`` and ``ProjectUpdateSummary`` need, minus project identity."""

    scan_count: int
    time_range_days: float
    first_scan_date: str
    last_scan_date: str
    total_updates: int
    updates_per_scan: float
    updates_per_month: float | None
    patch_updates: int
    minor_updates: int
    major_updates: int
    unknown_updates: int
    downgrade_updates: int
    granularity_ratio: dict[str, float]
    avg_days_between_scans: float
    total_outdated_detected: int
    outdated_resolved: int
    update_coverage_pct: float | None
    trend_direction: str
    trend_detail: str
    dominant_ecosystem: str | None
    scan_timeline: list[ScanTimelineEntry]
    recent_updates: list[DependencyUpdateEvent]

    def to_metrics(
        self,
        project_id: str,
        project_name: str,
        *,
        branch: str | None = None,
        slowest_packages: Sequence[SlowPackage] = (),
        upstream: UpstreamCadenceMetrics | None = None,
    ) -> UpdateFrequencyMetrics:
        return UpdateFrequencyMetrics(
            project_id=project_id,
            project_name=project_name,
            branch=branch,
            scan_count=self.scan_count,
            time_range_days=self.time_range_days,
            first_scan_date=self.first_scan_date,
            last_scan_date=self.last_scan_date,
            total_updates=self.total_updates,
            updates_per_scan=self.updates_per_scan,
            updates_per_month=self.updates_per_month,
            patch_updates=self.patch_updates,
            minor_updates=self.minor_updates,
            major_updates=self.major_updates,
            unknown_updates=self.unknown_updates,
            downgrade_updates=self.downgrade_updates,
            granularity_ratio=self.granularity_ratio,
            avg_days_between_scans=self.avg_days_between_scans,
            total_outdated_detected=self.total_outdated_detected,
            outdated_resolved=self.outdated_resolved,
            update_coverage_pct=self.update_coverage_pct,
            trend_direction=self.trend_direction,
            trend_detail=self.trend_detail,
            dominant_ecosystem=self.dominant_ecosystem,
            scan_timeline=self.scan_timeline,
            slowest_packages=list(slowest_packages),
            recent_updates=self.recent_updates,
            upstream_releases_last_12m_median=(upstream.upstream_releases_last_12m_median if upstream else None),
            upstream_days_between_releases_median=(
                upstream.upstream_days_between_releases_median if upstream else None
            ),
            upstream_days_since_latest_release_median=(
                upstream.upstream_days_since_latest_release_median if upstream else None
            ),
            adoption_latency_days_median=(upstream.adoption_latency_days_median if upstream else None),
        )

    def to_summary(
        self,
        project_id: str,
        project_name: str,
        team_name: str | None = None,
        *,
        branch: str | None = None,
        window_days: int,
    ) -> ProjectUpdateSummary:
        """A folded window is by definition measured, so the row is always ``ready``."""
        return ProjectUpdateSummary(
            project_id=project_id,
            project_name=project_name,
            team_name=team_name,
            data_status="ready",
            branch=branch,
            window_days=window_days,
            scan_count=self.scan_count,
            updates_per_month=self.updates_per_month,
            update_coverage_pct=self.update_coverage_pct,
            patch_ratio=self.granularity_ratio.get("patch", 0.0),
            trend_direction=self.trend_direction,
            total_updates=self.total_updates,
            total_outdated=self.total_outdated_detected,
            last_scan_date=self.last_scan_date,
        )


def select_window(deltas: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Narrow ``scan_update_deltas`` docs of one branch to a window that can be summed.

    Input must be one project, one branch, oldest first — a reversed or
    branch-mixed window would otherwise fold into negative cadences and
    cross-branch version differences counted as updates.

    SBOM-less scans and writer failures drop out: a missing measurement is
    not a measurement of zero, and keeping it would add a structural
    zero-update bar. The chain is then cut back to the newest run of scans
    that really do follow one another, and same-commit CI retries collapse
    into the first scan of their run. ``window[0]`` is the anchor: its update
    counts are dropped because they compare against a scan outside the window,
    while its id, date and outdated count still enter the fold.
    """
    _reject_broken_contract(deltas)
    usable = [d for d in deltas if int(d.get("dep_count", 0)) > 0 and not d.get("error")]
    return collapse_same_commit_runs(_contiguous_tail(usable))


def fold_window(
    window: Sequence[dict[str, Any]],
    baseline_outdated: set[str] | None,
    window_days: int | None,
) -> FoldedWindow:
    """Fold a window from ``select_window`` into one project's metrics.

    ``baseline_outdated`` is the full outdated set of ``window[0]``, or None
    when that scan carried no outdated analysis. ``window_days`` is the
    calendar span the caller selected on, or None when it asked for a fixed
    number of scans instead.
    """
    if len(window) < 2:
        return _short_window(window)

    timeline = [_timeline_entry(window[0], baseline=True)]
    timeline.extend(_timeline_entry(delta, baseline=False) for delta in window[1:])

    kinds: Counter[str] = Counter()
    for delta in window[1:]:
        updates = delta.get("updates") or {}
        for kind in (*_UPDATE_KINDS, "downgrade"):
            kinds[kind] += int(updates.get(kind, 0))

    ever_outdated, ever_resolved = _outdated_movement(window, baseline_outdated)

    total_updates = sum(kinds[kind] for kind in _UPDATE_KINDS)
    num_intervals = len(window) - 1

    first_date = as_utc(window[0]["scan_created_at"])
    last_date = as_utc(window[-1]["scan_created_at"])
    raw_range_days = (last_date - first_date).total_seconds() / 86400.0

    resolved_count = len(ever_outdated & ever_resolved)
    trend_direction, trend_detail = compute_trend(timeline)

    return FoldedWindow(
        scan_count=len(window),
        # Floored at one day so the rendered span never reads as zero.
        time_range_days=round(max(1.0, raw_range_days), 2),
        first_scan_date=first_date.isoformat(),
        last_scan_date=last_date.isoformat(),
        total_updates=total_updates,
        updates_per_scan=round(total_updates / num_intervals, 2),
        updates_per_month=updates_per_month(total_updates, window_days),
        patch_updates=kinds["patch"],
        minor_updates=kinds["minor"],
        major_updates=kinds["major"],
        unknown_updates=kinds["unknown"],
        downgrade_updates=kinds["downgrade"],
        granularity_ratio=granularity_ratio(kinds, total_updates),
        # Cadence reports the real average interval, not the floored range.
        avg_days_between_scans=round(raw_range_days / num_intervals, 1),
        total_outdated_detected=len(ever_outdated),
        outdated_resolved=resolved_count,
        update_coverage_pct=(round(resolved_count / len(ever_outdated) * 100, 1) if ever_outdated else None),
        trend_direction=trend_direction,
        trend_detail=trend_detail,
        dominant_ecosystem=_dominant_ecosystem(window[-1].get("eco") or {}),
        scan_timeline=timeline,
        recent_updates=_recent_updates(window[1:]),
    )


def _reject_broken_contract(deltas: Sequence[dict[str, Any]]) -> None:
    """Guard the two mixups that silently produce plausible-looking wrong numbers."""
    scopes = {(d["project_id"], d["branch"]) for d in deltas}
    if len(scopes) > 1:
        raise ValueError(f"deltas span more than one project/branch: {sorted(scopes)}")
    for older, newer in pairwise(deltas):
        if as_utc(newer["scan_created_at"]) < as_utc(older["scan_created_at"]):
            raise ValueError(f"deltas must be ordered oldest first; {newer['_id']} precedes {older['_id']}")


def _contiguous_tail(deltas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The newest run of deltas that really were diffed against one another.

    Every count of a delta describes the interval to its recorded predecessor.
    Where that link skips a scan the window no longer tiles the time range, so
    summing it would count one interval twice. Truncating rather than dropping
    the offending delta keeps every retained number exact and keeps the newest
    scans, which is what the tab is asked about.
    """
    start = len(deltas) - 1
    while start > 0 and deltas[start].get("prev_scan_id") == deltas[start - 1]["_id"]:
        start -= 1
    if start > 0:
        logger.info(
            "Update-frequency chain breaks at scan %s; folding only its %d newest scans",
            deltas[start]["_id"],
            len(deltas) - start,
        )
    return deltas[start:]


def _outdated_movement(
    window: Sequence[dict[str, Any]], baseline_outdated: set[str] | None
) -> tuple[set[str], set[str]]:
    """Packages ever outdated and ever brought up to date across the window.

    Both lists are summed unconditionally because the writer already leaves them
    empty wherever a comparison lacked a measurement, and reports the full
    outdated set of a scan whose predecessor carried none. Skipping such a scan
    here instead would keep packages that went outdated across the unmeasured
    stretch out of the denominator while later resolutions kept counting.
    """
    ever_outdated = set(baseline_outdated or ())
    ever_resolved: set[str] = set()
    for delta in window[1:]:
        ever_outdated.update(delta.get("outdated_added") or [])
        ever_resolved.update(delta.get("outdated_resolved") or [])
    return ever_outdated, ever_resolved


def _short_window(window: Sequence[dict[str, Any]]) -> FoldedWindow:
    """A window with fewer than two scans supports no comparison at all."""
    scan_date = as_utc(window[0]["scan_created_at"]).isoformat() if window else ""
    return FoldedWindow(
        scan_count=len(window),
        time_range_days=0.0,
        first_scan_date=scan_date,
        last_scan_date=scan_date,
        total_updates=0,
        updates_per_scan=0.0,
        updates_per_month=None,
        patch_updates=0,
        minor_updates=0,
        major_updates=0,
        unknown_updates=0,
        downgrade_updates=0,
        granularity_ratio={"patch": 0.0, "minor": 0.0, "major": 0.0, "unknown": 0.0},
        avg_days_between_scans=0.0,
        total_outdated_detected=0,
        outdated_resolved=0,
        update_coverage_pct=None,
        trend_direction="unknown",
        trend_detail=_NOT_ENOUGH_SCANS,
        dominant_ecosystem=None,
        scan_timeline=[],
        recent_updates=[],
    )


def _timeline_entry(delta: dict[str, Any], *, baseline: bool) -> ScanTimelineEntry:
    updates: dict[str, Any] = {} if baseline else (delta.get("updates") or {})
    counts = {kind: int(updates.get(kind, 0)) for kind in _UPDATE_KINDS}
    outdated_count = delta.get("outdated_count")
    return ScanTimelineEntry(
        scan_id=str(delta["_id"]),
        date=as_utc(delta["scan_created_at"]).isoformat(),
        updates_count=sum(counts.values()),
        outdated_count=None if outdated_count is None else int(outdated_count),
        patch=counts["patch"],
        minor=counts["minor"],
        major=counts["major"],
        unknown=counts["unknown"],
        downgrades=int(updates.get("downgrade", 0)),
    )


def _dominant_ecosystem(eco: dict[str, Any]) -> str | None:
    """Ecosystem owning >=70% of the newest scan's classified deps; ``"mixed"`` otherwise.

    Only the newest scan counts: dominance describes what the project holds now,
    while summing the window would let long-removed deps sway it.
    """
    counts = {name: int(n) for name, n in eco.items() if name and name != "unknown" and int(n) > 0}
    if not counts:
        return None
    top_type, top_count = max(counts.items(), key=lambda item: item[1])
    if top_count / sum(counts.values()) >= ECOSYSTEM_DOMINANCE_THRESHOLD:
        return top_type
    return "mixed"


def _recent_updates(deltas: Sequence[dict[str, Any]]) -> list[DependencyUpdateEvent]:
    """Newest-first update events drawn from the per-scan samples."""
    events: list[DependencyUpdateEvent] = []
    for delta in reversed(deltas):
        prev_created_at = delta.get("prev_created_at")
        if prev_created_at is None:
            continue
        scan_date = as_utc(delta["scan_created_at"])
        previous_scan_date = as_utc(prev_created_at)
        days_between = max(1, (scan_date - previous_scan_date).days)
        for sample in delta.get("updates_sample") or []:
            events.append(
                DependencyUpdateEvent(
                    package_name=sample["n"],
                    package_type=sample["t"],
                    purl=sample.get("p"),
                    old_version=sample["ov"],
                    new_version=sample["nv"],
                    update_type=sample["k"],
                    scan_date=scan_date.isoformat(),
                    previous_scan_date=previous_scan_date.isoformat(),
                    days_between_scans=days_between,
                    was_outdated=bool(sample["wo"]),
                )
            )
            if len(events) == _RECENT_UPDATES_LIMIT:
                return events
    return events
