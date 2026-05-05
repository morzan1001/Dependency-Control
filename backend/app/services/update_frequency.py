"""
Update Frequency Analysis Service

Computes metrics about how regularly and incrementally teams update their
dependencies, by comparing dependency versions across consecutive scans.

Memory strategy: instead of loading all dependencies for all scans at once
(which can exceed hundreds of thousands of documents for large projects), we
load and compare one scan pair at a time, keeping peak memory to 2×deps/scan.
"""

import asyncio
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Limit concurrent per-project computations in the comparison endpoint to
# avoid firing many large MongoDB queries simultaneously.
_COMPARISON_SEMAPHORE = asyncio.Semaphore(3)

from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.scans import ScanRepository
from app.schemas.analytics import (
    DependencyUpdateEvent,
    ProjectUpdateSummary,
    ScanTimelineEntry,
    SlowPackage,
    UpdateFrequencyComparison,
    UpdateFrequencyMetrics,
)

logger = logging.getLogger(__name__)

# Regex for semver-like versions: X.Y.Z with optional pre-release
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?")

_DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "purl": 1, "scan_id": 1}


def classify_version_change(old_version: str, new_version: str) -> str:
    """
    Classify a version change as patch, minor, major, or unknown.

    Handles semver-like patterns (X.Y.Z). Returns "unknown" for
    versions that cannot be parsed (e.g. calver, hashes).
    """
    old_match = _SEMVER_RE.match(old_version)
    new_match = _SEMVER_RE.match(new_version)

    if not old_match or not new_match:
        return "unknown"

    old_major, old_minor, old_patch = (
        int(old_match.group(1)),
        int(old_match.group(2)),
        int(old_match.group(3) or 0),
    )
    new_major, new_minor, new_patch = (
        int(new_match.group(1)),
        int(new_match.group(2)),
        int(new_match.group(3) or 0),
    )

    if new_major != old_major:
        return "major"
    if new_minor != old_minor:
        return "minor"
    if new_patch != old_patch:
        return "patch"
    return "patch"


def _pregroup_deps_by_scan(
    all_deps: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Dict[str, str]]]:
    """
    Pre-group dependencies by scan_id into {scan_id: {pkg_name: {version, type, purl}}}.
    """
    grouped: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(dict)
    for dep in all_deps:
        scan_id = dep.get("scan_id", "")
        name = dep.get("name", "")
        if scan_id and name:
            grouped[scan_id][name] = {
                "version": dep.get("version", ""),
                "type": dep.get("type", "unknown"),
                "purl": dep.get("purl", ""),
            }
    return dict(grouped)


def _extract_outdated_set(analysis_result: Any) -> set:
    """Extract set of outdated package names from an outdated_packages analysis result."""
    outdated_names: set = set()
    if not analysis_result:
        return outdated_names

    result_data = getattr(analysis_result, "result", None)
    if isinstance(result_data, dict):
        for entry in result_data.get("outdated_dependencies", []):
            component = entry.get("component", "")
            if component:
                outdated_names.add(component)
    return outdated_names


def _build_outdated_maps(
    outdated_results: list,
) -> Tuple[Dict[str, set], Dict[str, Dict[str, str]]]:
    """
    Build per-scan outdated sets and a package->latest version info map
    from outdated_packages analysis results.

    Returns:
        (outdated_by_scan, package_latest_info)
    """
    outdated_by_scan: Dict[str, set] = {}
    package_latest_info: Dict[str, Dict[str, str]] = {}

    for ar in outdated_results:
        outdated_by_scan[ar.scan_id] = _extract_outdated_set(ar)

        result_data = getattr(ar, "result", {}) or {}
        for entry in result_data.get("outdated_dependencies", []):
            comp = entry.get("component", "")
            if comp:
                package_latest_info[comp] = {
                    "current_version": entry.get("current_version", ""),
                    "latest_version": entry.get("latest_version", ""),
                }

    return outdated_by_scan, package_latest_info


def _compare_scan_pair(
    deps_by_scan: Dict[str, Dict[str, Dict[str, str]]],
    prev_scan_id: str,
    prev_scan_date: datetime,
    curr_scan_id: str,
    curr_scan_date: datetime,
    prev_outdated: set,
) -> List[DependencyUpdateEvent]:
    """Compare dependencies between two consecutive scans and return update events."""
    days_between = max(1, (curr_scan_date - prev_scan_date).days)

    prev_deps = deps_by_scan.get(prev_scan_id, {})
    curr_deps = deps_by_scan.get(curr_scan_id, {})

    events: List[DependencyUpdateEvent] = []
    for pkg_name, curr_info in curr_deps.items():
        prev_info = prev_deps.get(pkg_name)
        if not prev_info or curr_info["version"] == prev_info["version"]:
            continue

        events.append(
            DependencyUpdateEvent(
                package_name=pkg_name,
                package_type=curr_info["type"],
                purl=curr_info["purl"] or None,
                old_version=prev_info["version"],
                new_version=curr_info["version"],
                update_type=classify_version_change(prev_info["version"], curr_info["version"]),
                scan_date=curr_scan_date.isoformat(),
                previous_scan_date=prev_scan_date.isoformat(),
                days_between_scans=days_between,
                was_outdated=pkg_name in prev_outdated,
            )
        )
    return events


def _build_timeline_entry(
    scan_id: str,
    scan_date: datetime,
    events: List[DependencyUpdateEvent],
    outdated_count: int,
) -> ScanTimelineEntry:
    """Build a timeline entry from a list of update events for a scan."""
    type_counts = Counter(e.update_type for e in events)
    return ScanTimelineEntry(
        scan_id=scan_id,
        date=scan_date.isoformat(),
        updates_count=len(events),
        outdated_count=outdated_count,
        patch=type_counts.get("patch", 0),
        minor=type_counts.get("minor", 0),
        major=type_counts.get("major", 0),
    )


def _compute_trend(
    scan_timeline: List[ScanTimelineEntry],
) -> Tuple[str, str]:
    """
    Compute trend by comparing the first half vs second half of scan timeline.

    Returns (direction, detail) tuple.
    """
    if len(scan_timeline) < 4:
        return "stable", "Not enough scans to determine trend (need at least 4)"

    mid = len(scan_timeline) // 2
    older = scan_timeline[:mid]
    newer = scan_timeline[mid:]

    older_avg_updates = sum(s.updates_count for s in older) / len(older)
    newer_avg_updates = sum(s.updates_count for s in newer) / len(newer)
    older_avg_outdated = sum(s.outdated_count for s in older) / len(older)
    newer_avg_outdated = sum(s.outdated_count for s in newer) / len(newer)

    update_improving = newer_avg_updates > older_avg_updates * 1.1
    outdated_improving = newer_avg_outdated < older_avg_outdated * 0.9
    update_deteriorating = newer_avg_updates < older_avg_updates * 0.9
    outdated_deteriorating = newer_avg_outdated > older_avg_outdated * 1.1

    if update_improving or outdated_improving:
        parts = []
        if update_improving:
            parts.append(f"Updates/scan: {older_avg_updates:.1f} → {newer_avg_updates:.1f}")
        if outdated_improving:
            parts.append(f"Outdated: {older_avg_outdated:.1f} → {newer_avg_outdated:.1f}")
        return "improving", ". ".join(parts)

    if update_deteriorating or outdated_deteriorating:
        parts = []
        if update_deteriorating:
            parts.append(f"Updates/scan: {older_avg_updates:.1f} → {newer_avg_updates:.1f}")
        if outdated_deteriorating:
            parts.append(f"Outdated: {older_avg_outdated:.1f} → {newer_avg_outdated:.1f}")
        return "deteriorating", ". ".join(parts)

    return "stable", (f"Consistent (~{newer_avg_updates:.1f} updates/scan, ~{newer_avg_outdated:.0f} outdated)")


def _aggregate_metrics(
    all_events: List[DependencyUpdateEvent],
    completed_scans: List[Dict[str, Any]],
    ever_outdated: set,
    ever_resolved: set,
    scan_timeline: List[ScanTimelineEntry],
    dep_type_map: Dict[str, str],
    package_outdated_counts: Dict[str, int],
    package_latest_info: Dict[str, Dict[str, str]],
    project_id: str,
    project_name: str,
) -> UpdateFrequencyMetrics:
    """Aggregate all collected data into the final metrics response."""
    total_updates = len(all_events)
    num_intervals = len(completed_scans) - 1

    first_date: datetime = completed_scans[0]["created_at"]
    last_date: datetime = completed_scans[-1]["created_at"]
    time_range_days = max(1, (last_date - first_date).days)
    time_range_months = time_range_days / 30.44

    type_counts = Counter(e.update_type for e in all_events)
    patch_total = type_counts.get("patch", 0)
    minor_total = type_counts.get("minor", 0)
    major_total = type_counts.get("major", 0)
    unknown_total = type_counts.get("unknown", 0)

    granularity_ratio = {
        "patch": round(patch_total / total_updates, 2) if total_updates else 0.0,
        "minor": round(minor_total / total_updates, 2) if total_updates else 0.0,
        "major": round(major_total / total_updates, 2) if total_updates else 0.0,
        "unknown": round(unknown_total / total_updates, 2) if total_updates else 0.0,
    }

    avg_days_between = time_range_days / num_intervals if num_intervals else 0

    total_outdated_detected = len(ever_outdated)
    outdated_resolved_count = len(ever_outdated & ever_resolved)
    update_coverage_pct = (
        round(outdated_resolved_count / total_outdated_detected * 100, 1) if total_outdated_detected else 0.0
    )

    trend_direction, trend_detail = _compute_trend(scan_timeline)

    slowest_packages = _build_slowest_packages(package_outdated_counts, package_latest_info, dep_type_map)
    recent_updates = sorted(all_events, key=lambda e: e.scan_date, reverse=True)[:30]

    return UpdateFrequencyMetrics(
        project_id=project_id,
        project_name=project_name,
        scan_count=len(completed_scans),
        time_range_days=time_range_days,
        first_scan_date=first_date.isoformat(),
        last_scan_date=last_date.isoformat(),
        total_updates=total_updates,
        updates_per_scan=round(total_updates / num_intervals, 2) if num_intervals else 0,
        updates_per_month=round(total_updates / time_range_months, 2) if time_range_months else 0,
        patch_updates=patch_total,
        minor_updates=minor_total,
        major_updates=major_total,
        unknown_updates=unknown_total,
        granularity_ratio=granularity_ratio,
        avg_days_between_scans=round(avg_days_between, 1),
        total_outdated_detected=total_outdated_detected,
        outdated_resolved=outdated_resolved_count,
        update_coverage_pct=update_coverage_pct,
        trend_direction=trend_direction,
        trend_detail=trend_detail,
        scan_timeline=scan_timeline,
        slowest_packages=slowest_packages,
        recent_updates=recent_updates,
    )


def _build_slowest_packages(
    package_outdated_counts: Dict[str, int],
    package_latest_info: Dict[str, Dict[str, str]],
    dep_type_map: Dict[str, str],
) -> List[SlowPackage]:
    """Build the list of slowest-to-update packages (most scans outdated)."""
    slowest = sorted(package_outdated_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    return [
        SlowPackage(
            name=pkg_name,
            type=dep_type_map.get(pkg_name, "unknown"),
            current_version=package_latest_info.get(pkg_name, {}).get("current_version"),
            latest_version=package_latest_info.get(pkg_name, {}).get("latest_version"),
            scans_outdated=count,
        )
        for pkg_name, count in slowest
    ]


def _empty_metrics(project_id: str, project_name: str, scan_count: int, scan_date: str) -> UpdateFrequencyMetrics:
    """Return empty metrics when there are fewer than 2 scans."""
    return UpdateFrequencyMetrics(
        project_id=project_id,
        project_name=project_name,
        scan_count=scan_count,
        time_range_days=0,
        first_scan_date=scan_date,
        last_scan_date=scan_date,
        total_updates=0,
        updates_per_scan=0.0,
        updates_per_month=0.0,
        patch_updates=0,
        minor_updates=0,
        major_updates=0,
        unknown_updates=0,
        granularity_ratio={"patch": 0.0, "minor": 0.0, "major": 0.0, "unknown": 0.0},
        avg_days_between_scans=0.0,
        total_outdated_detected=0,
        outdated_resolved=0,
        update_coverage_pct=0.0,
        trend_direction="stable",
        trend_detail="Not enough scans to analyze (need at least 2)",
        scan_timeline=[],
        slowest_packages=[],
        recent_updates=[],
    )


async def compute_update_frequency(
    project_id: str,
    project_name: str,
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    max_scans: int = 20,
) -> UpdateFrequencyMetrics:
    """
    Compute update frequency metrics for a project.

    Dependencies are loaded one scan pair at a time to keep peak memory
    bounded to 2×deps_per_scan regardless of how many scans are analysed.
    """
    scans_raw = await scan_repo.find_by_project(
        project_id,
        limit=max_scans,
        sort_by="created_at",
        sort_order=1,
        projection={"_id": 1, "created_at": 1, "status": 1},
    )
    completed_scans = [s for s in scans_raw if s.get("status") == "completed"]

    if len(completed_scans) < 2:
        first_date_str = completed_scans[0]["created_at"].isoformat() if completed_scans else ""
        return _empty_metrics(project_id, project_name, len(completed_scans), first_date_str)

    scan_ids = [s["_id"] for s in completed_scans]

    # Fetch lightweight outdated analysis results upfront (one doc per scan)
    outdated_results = await analysis_repo.find_many(
        {"scan_id": {"$in": scan_ids}, "analyzer_name": "outdated_packages"},
        limit=max_scans,
    )
    outdated_by_scan, package_latest_info = _build_outdated_maps(outdated_results)

    # Accumulators
    all_update_events: List[DependencyUpdateEvent] = []
    scan_timeline: List[ScanTimelineEntry] = []
    package_outdated_counts: Dict[str, int] = defaultdict(int)
    dep_type_map: Dict[str, str] = {}
    ever_outdated: set = set()
    ever_resolved: set = set()

    # First scan: no events yet, just bootstrap outdated tracking
    first_scan = completed_scans[0]
    first_outdated = outdated_by_scan.get(first_scan["_id"], set())
    for pkg in first_outdated:
        package_outdated_counts[pkg] += 1
        ever_outdated.add(pkg)
    scan_timeline.append(
        _build_timeline_entry(first_scan["_id"], first_scan["created_at"], [], len(first_outdated))
    )

    # Process each consecutive pair — load only 2 scans' deps at a time
    for i in range(1, len(completed_scans)):
        prev_scan = completed_scans[i - 1]
        curr_scan = completed_scans[i]

        pair_deps = await dep_repo.find_all(
            {"scan_id": {"$in": [prev_scan["_id"], curr_scan["_id"]]}},
            projection=_DEP_PROJECTION,
        )
        deps_by_scan = _pregroup_deps_by_scan(pair_deps)

        # Accumulate type info (used later for slowest-packages lookup)
        for scan_deps in deps_by_scan.values():
            for name, info in scan_deps.items():
                if name not in dep_type_map:
                    dep_type_map[name] = info.get("type", "unknown")

        curr_outdated = outdated_by_scan.get(curr_scan["_id"], set())
        prev_outdated = outdated_by_scan.get(prev_scan["_id"], set())

        for pkg in curr_outdated:
            package_outdated_counts[pkg] += 1
            ever_outdated.add(pkg)

        events = _compare_scan_pair(
            deps_by_scan,
            prev_scan["_id"],
            prev_scan["created_at"],
            curr_scan["_id"],
            curr_scan["created_at"],
            prev_outdated,
        )

        for e in events:
            if e.was_outdated:
                ever_resolved.add(e.package_name)

        all_update_events.extend(events)
        scan_timeline.append(
            _build_timeline_entry(curr_scan["_id"], curr_scan["created_at"], events, len(curr_outdated))
        )

    return _aggregate_metrics(
        all_update_events,
        completed_scans,
        ever_outdated,
        ever_resolved,
        scan_timeline,
        dep_type_map,
        package_outdated_counts,
        package_latest_info,
        project_id,
        project_name,
    )


async def compute_update_frequency_comparison(
    projects: List[Dict[str, Any]],
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    max_scans: int = 10,
) -> UpdateFrequencyComparison:
    """
    Compute update frequency comparison across multiple projects.

    At most _COMPARISON_SEMAPHORE concurrent per-project computations run at
    once to avoid saturating MongoDB with simultaneous large queries.
    """

    async def _compute_single(project: Dict[str, Any]) -> Optional[ProjectUpdateSummary]:
        project_id = project.get("_id") or project.get("id", "")
        project_name = project.get("name", "")
        team_name = project.get("team_name")

        async with _COMPARISON_SEMAPHORE:
            try:
                metrics = await compute_update_frequency(
                    project_id=project_id,
                    project_name=project_name,
                    scan_repo=scan_repo,
                    dep_repo=dep_repo,
                    analysis_repo=analysis_repo,
                    max_scans=max_scans,
                )
            except Exception:
                logger.warning(f"Failed to compute update frequency for project {project_id}", exc_info=True)
                return None

            if metrics.scan_count < 2:
                return None

            return ProjectUpdateSummary(
                project_id=metrics.project_id,
                project_name=metrics.project_name,
                team_name=team_name,
                scan_count=metrics.scan_count,
                updates_per_month=metrics.updates_per_month,
                update_coverage_pct=metrics.update_coverage_pct,
                patch_ratio=metrics.granularity_ratio.get("patch", 0),
                trend_direction=metrics.trend_direction,
                total_outdated=metrics.total_outdated_detected,
                last_scan_date=metrics.last_scan_date,
            )

    results = await asyncio.gather(*[_compute_single(p) for p in projects], return_exceptions=True)
    summaries: List[ProjectUpdateSummary] = [s for s in results if isinstance(s, ProjectUpdateSummary)]

    summaries.sort(key=lambda s: (s.update_coverage_pct, s.updates_per_month), reverse=True)

    if summaries:
        avg_updates = sum(s.updates_per_month for s in summaries) / len(summaries)
        avg_coverage = sum(s.update_coverage_pct for s in summaries) / len(summaries)
        best = summaries[0].project_name
        worst = summaries[-1].project_name
    else:
        avg_updates = 0.0
        avg_coverage = 0.0
        best = None
        worst = None

    return UpdateFrequencyComparison(
        projects=summaries,
        team_avg_updates_per_month=round(avg_updates, 2),
        team_avg_coverage_pct=round(avg_coverage, 1),
        best_project=best,
        worst_project=worst,
    )
