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
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple

from packaging.version import InvalidVersion, Version

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
from app.services.analyzers.purl_utils import parse_purl
from app.services.release_history import (
    Observation,
    ReleaseHistoryFetcher,
    UpstreamCadenceMetrics,
    aggregate_upstream_metrics,
)

logger = logging.getLogger(__name__)

# Limit concurrent per-project computations in the comparison endpoint to
# avoid firing many large MongoDB queries simultaneously. Lazy-init so the
# semaphore binds to whichever event loop is actually running (matters for
# pytest-asyncio tests that create a fresh loop per test).
_COMPARISON_CONCURRENCY = 3
_comparison_semaphore: Optional[asyncio.Semaphore] = None


def _get_comparison_semaphore() -> asyncio.Semaphore:
    global _comparison_semaphore
    if _comparison_semaphore is None:
        _comparison_semaphore = asyncio.Semaphore(_COMPARISON_CONCURRENCY)
    return _comparison_semaphore

_DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "purl": 1, "scan_id": 1}


def _release_tuple(version: Version) -> Tuple[int, int, int]:
    """Return the (major, minor, patch) tuple, padding shorter releases with 0."""
    release = version.release
    return (
        release[0] if len(release) > 0 else 0,
        release[1] if len(release) > 1 else 0,
        release[2] if len(release) > 2 else 0,
    )


def classify_version_change(old_version: str, new_version: str) -> str:
    """
    Classify a version change as none, patch, minor, major, or unknown.

    Uses PEP 440 parsing so pre-release identifiers (1.0.0-beta1, 1.0.0rc2)
    are not collapsed into their underlying release tuple. Returns:
      - "none"    if the parsed versions are equal
      - "major" / "minor" / "patch"  by which release component changed
      - "patch"   if only pre-release / post-release / local segments differ
      - "unknown" if either version is not PEP 440 parseable
    """
    try:
        old_v = Version(old_version)
        new_v = Version(new_version)
    except InvalidVersion:
        return "unknown"

    if old_v == new_v:
        return "none"

    old_major, old_minor, old_patch = _release_tuple(old_v)
    new_major, new_minor, new_patch = _release_tuple(new_v)

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


async def _load_outdated_for_scan(
    analysis_repo: AnalysisResultRepository,
    scan_id: str,
    package_latest_info: Dict[str, Dict[str, str]],
) -> set:
    """Load the outdated_packages analysis result for one scan, updating
    `package_latest_info` in-place with the latest version info encountered,
    and returning the set of outdated component names.

    Streaming variant of the previous bulk loader: keeps memory bounded to
    one scan's worth of outdated entries instead of all scans simultaneously.
    """
    results = await analysis_repo.find_many(
        {"scan_id": scan_id, "analyzer_name": "outdated_packages"},
        limit=1,
    )
    outdated_names: set = set()
    if not results:
        return outdated_names

    result_data = getattr(results[0], "result", {}) or {}
    for entry in result_data.get("outdated_dependencies", []):
        comp = entry.get("component", "")
        if not comp:
            continue
        outdated_names.add(comp)
        # Last-write-wins is fine: we only need one consistent
        # current/latest pair per package for the slowest_packages list.
        package_latest_info[comp] = {
            "current_version": entry.get("current_version", ""),
            "latest_version": entry.get("latest_version", ""),
        }
    return outdated_names


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

        update_type = classify_version_change(prev_info["version"], curr_info["version"])
        # "none" means the versions parse to the same PEP 440 identity
        # (e.g. "v1.0.0" vs "1.0.0") — not a real update event.
        if update_type == "none":
            continue

        events.append(
            DependencyUpdateEvent(
                package_name=pkg_name,
                package_type=curr_info["type"],
                purl=curr_info["purl"] or None,
                old_version=prev_info["version"],
                new_version=curr_info["version"],
                update_type=update_type,
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
        return "unknown", "Not enough scans to determine trend (need at least 4)"

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
    completed_scans: List[Dict[str, Any]],
    ever_outdated: set,
    ever_resolved: set,
    scan_timeline: List[ScanTimelineEntry],
    dep_type_map: Dict[str, str],
    package_outdated_counts: Dict[str, int],
    package_latest_info: Dict[str, Dict[str, str]],
    project_id: str,
    project_name: str,
    *,
    type_counter: Optional[Counter] = None,
    recent_events: Optional[List[DependencyUpdateEvent]] = None,
    all_events: Optional[List[DependencyUpdateEvent]] = None,
    upstream: Optional[UpstreamCadenceMetrics] = None,
) -> UpdateFrequencyMetrics:
    """Aggregate streamed counters into the final metrics response.

    The orchestrator accumulates ``type_counter`` and a bounded ring buffer
    of recent events while iterating scans, so peak memory does not depend
    on the number of update events. The legacy ``all_events`` argument is
    accepted for tests that still construct the metrics directly from a
    list — when supplied it overrides the streamed values.
    """
    if all_events is not None:
        type_counter = Counter(e.update_type for e in all_events)
        recent_events = sorted(all_events, key=lambda e: e.scan_date, reverse=True)[:30]
        total_updates = len(all_events)
    else:
        if type_counter is None or recent_events is None:
            raise TypeError(
                "_aggregate_metrics requires either `all_events` or both "
                "`type_counter` and `recent_events`"
            )
        total_updates = sum(type_counter.values())

    num_intervals = len(completed_scans) - 1

    first_date: datetime = completed_scans[0]["created_at"]
    last_date: datetime = completed_scans[-1]["created_at"]
    time_range_days = max(1, (last_date - first_date).days)
    time_range_months = time_range_days / 30.44

    patch_total = type_counter.get("patch", 0)
    minor_total = type_counter.get("minor", 0)
    major_total = type_counter.get("major", 0)
    unknown_total = type_counter.get("unknown", 0)

    granularity_ratio = {
        "patch": round(patch_total / total_updates, 2) if total_updates else 0.0,
        "minor": round(minor_total / total_updates, 2) if total_updates else 0.0,
        "major": round(major_total / total_updates, 2) if total_updates else 0.0,
        "unknown": round(unknown_total / total_updates, 2) if total_updates else 0.0,
    }

    avg_days_between = time_range_days / num_intervals if num_intervals else 0

    total_outdated_detected = len(ever_outdated)
    outdated_resolved_count = len(ever_outdated & ever_resolved)
    # None means "no outdated packages were ever detected" — semantic N/A.
    # Distinct from 0.0 ("outdated detected but nothing resolved").
    update_coverage_pct: Optional[float] = (
        round(outdated_resolved_count / total_outdated_detected * 100, 1)
        if total_outdated_detected
        else None
    )

    trend_direction, trend_detail = _compute_trend(scan_timeline)

    slowest_packages = _build_slowest_packages(package_outdated_counts, package_latest_info, dep_type_map)

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
        recent_updates=recent_events,
        upstream_releases_last_12m_median=(
            upstream.upstream_releases_last_12m_median if upstream else None
        ),
        upstream_days_between_releases_median=(
            upstream.upstream_days_between_releases_median if upstream else None
        ),
        upstream_days_since_latest_release_median=(
            upstream.upstream_days_since_latest_release_median if upstream else None
        ),
        adoption_latency_days_median=(
            upstream.adoption_latency_days_median if upstream else None
        ),
        dominant_ecosystem=_dominant_ecosystem(dep_type_map),
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
        update_coverage_pct=None,
        trend_direction="unknown",
        trend_detail="Not enough scans to analyze (need at least 2)",
        scan_timeline=[],
        slowest_packages=[],
        recent_updates=[],
    )


_RECENT_EVENTS_BUFFER_SIZE = 30

# Defensive cap on the (package, version) -> first_scan_date map used for
# adoption-latency. The map only grows with *new* (pkg, version) pairs, so
# 10k entries is far above realistic project sizes; the bound guards against
# pathological histories with extreme version churn.
_MAX_OBSERVATIONS = 10_000

# Share of classified deps a single ecosystem must hold to "win" the project.
# Below the threshold the project is labelled "mixed" instead.
_ECOSYSTEM_DOMINANCE_THRESHOLD = 0.7


def _dominant_ecosystem(dep_type_map: Dict[str, str]) -> Optional[str]:
    """Pick the registry/ecosystem that owns >=70% of the project's classified deps.

    Returns ``None`` when there are no classified deps at all, ``"mixed"``
    when no single ecosystem clears the threshold, otherwise the winning
    ecosystem name (e.g. "pypi", "npm", "maven"). The "unknown" type is
    excluded from the count so that missing-PURL noise doesn't tilt the
    classification.
    """
    classified = [t for t in dep_type_map.values() if t and t != "unknown"]
    if not classified:
        return None
    counts = Counter(classified)
    top_type, top_count = counts.most_common(1)[0]
    if top_count / len(classified) >= _ECOSYSTEM_DOMINANCE_THRESHOLD:
        return top_type
    return "mixed"


_DEFAULT_HARD_LIMIT = 1000


@dataclass
class _AccumulatorState:
    """All state the streaming loop accumulates as it walks scan pairs.

    Bundling these into one object keeps the orchestrator function from
    juggling ten loose locals and lets each helper take a single argument.
    """

    type_counter: Counter = field(default_factory=Counter)
    recent_events_buffer: Deque[DependencyUpdateEvent] = field(
        default_factory=lambda: deque(maxlen=_RECENT_EVENTS_BUFFER_SIZE)
    )
    scan_timeline: List[ScanTimelineEntry] = field(default_factory=list)
    package_outdated_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    package_latest_info: Dict[str, Dict[str, str]] = field(default_factory=dict)
    dep_type_map: Dict[str, str] = field(default_factory=dict)
    ever_outdated: set = field(default_factory=set)
    ever_resolved: set = field(default_factory=set)
    first_seen_versions: Dict[Tuple[str, str], datetime] = field(default_factory=dict)
    package_purls: Dict[str, str] = field(default_factory=dict)

    def accumulate_types(self, deps: Dict[str, Dict[str, str]]) -> None:
        for name, info in deps.items():
            if name not in self.dep_type_map:
                self.dep_type_map[name] = info.get("type", "unknown")
            purl = info.get("purl") or ""
            if purl and name not in self.package_purls:
                self.package_purls[name] = purl

    def record_outdated(self, outdated: set) -> None:
        for pkg in outdated:
            self.package_outdated_counts[pkg] += 1
            self.ever_outdated.add(pkg)

    def absorb_events(
        self, events: List[DependencyUpdateEvent], curr_scan_date: datetime
    ) -> None:
        for e in events:
            if e.was_outdated:
                self.ever_resolved.add(e.package_name)
            self.type_counter[e.update_type] += 1
            self.recent_events_buffer.append(e)
            if len(self.first_seen_versions) < _MAX_OBSERVATIONS:
                key = (e.package_name, e.new_version)
                if key not in self.first_seen_versions:
                    self.first_seen_versions[key] = curr_scan_date


async def _load_completed_scans(
    scan_repo: ScanRepository,
    project_id: str,
    max_scans: int,
    since: Optional[datetime],
    hard_limit: int,
) -> List[Dict[str, Any]]:
    """Resolve the scan window into a chronologically ordered list of completed scans.

    When ``since`` is set the calendar window dominates and ``max_scans`` is
    ignored; ``hard_limit`` is the safety cap. When ``since`` is None the
    newest ``max_scans`` are taken.
    """
    fetch_limit = hard_limit if since is not None else max_scans
    scans_raw = await scan_repo.find_by_project(
        project_id,
        limit=fetch_limit,
        sort_by="created_at",
        sort_order=-1,
        projection={"_id": 1, "created_at": 1, "status": 1},
    )
    if since is not None:
        scans_raw = [s for s in scans_raw if s["created_at"] >= since]
    scans_raw.reverse()  # oldest -> newest for the streaming loop
    return [s for s in scans_raw if s.get("status") == "completed"]


async def compute_update_frequency(
    project_id: str,
    project_name: str,
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    max_scans: int = 20,
    since: Optional[datetime] = None,
    release_fetcher: Optional[ReleaseHistoryFetcher] = None,
    hard_limit: int = _DEFAULT_HARD_LIMIT,
) -> UpdateFrequencyMetrics:
    """
    Compute update frequency metrics for a project.

    Streaming model: dependencies and outdated-results are loaded one scan
    (or scan pair) at a time. Update events are accumulated as a Counter
    plus a bounded deque, so peak memory does not grow with the number of
    update events or scans analysed.

    Selection:
        - When ``since`` is set, every completed scan with ``created_at >= since``
          is analysed, bounded only by ``hard_limit`` (default 1000) as a
          safety cap. ``max_scans`` is *ignored* in this mode — the calendar
          window is the user's stated intent.
        - When ``since`` is None, the most recent ``max_scans`` completed scans
          are analysed.
    """
    completed_scans = await _load_completed_scans(
        scan_repo, project_id, max_scans, since, hard_limit
    )

    if len(completed_scans) < 2:
        first_date_str = completed_scans[0]["created_at"].isoformat() if completed_scans else ""
        return _empty_metrics(project_id, project_name, len(completed_scans), first_date_str)

    state = _AccumulatorState()

    async def _load_scan_deps(scan_id: str) -> Dict[str, Dict[str, str]]:
        docs = await dep_repo.find_all({"scan_id": scan_id}, projection=_DEP_PROJECTION)
        return _pregroup_deps_by_scan(docs).get(scan_id, {})

    # Bootstrap: load first scan's deps + outdated. Subsequent iterations
    # roll the previous scan's data forward instead of reloading.
    first_scan = completed_scans[0]
    prev_deps = await _load_scan_deps(first_scan["_id"])
    state.accumulate_types(prev_deps)
    prev_outdated = await _load_outdated_for_scan(
        analysis_repo, first_scan["_id"], state.package_latest_info
    )
    state.record_outdated(prev_outdated)
    state.scan_timeline.append(
        _build_timeline_entry(first_scan["_id"], first_scan["created_at"], [], len(prev_outdated))
    )

    for i in range(1, len(completed_scans)):
        prev_scan = completed_scans[i - 1]
        curr_scan = completed_scans[i]

        curr_deps = await _load_scan_deps(curr_scan["_id"])
        state.accumulate_types(curr_deps)

        curr_outdated = await _load_outdated_for_scan(
            analysis_repo, curr_scan["_id"], state.package_latest_info
        )
        state.record_outdated(curr_outdated)

        events = _compare_scan_pair(
            {prev_scan["_id"]: prev_deps, curr_scan["_id"]: curr_deps},
            prev_scan["_id"],
            prev_scan["created_at"],
            curr_scan["_id"],
            curr_scan["created_at"],
            prev_outdated,
        )
        state.absorb_events(events, curr_scan["created_at"])
        state.scan_timeline.append(
            _build_timeline_entry(curr_scan["_id"], curr_scan["created_at"], events, len(curr_outdated))
        )

        prev_deps = curr_deps
        prev_outdated = curr_outdated

    upstream = await _maybe_fetch_upstream_cadence(
        release_fetcher, state.package_purls, state.first_seen_versions
    )

    return _aggregate_metrics(
        completed_scans,
        state.ever_outdated,
        state.ever_resolved,
        state.scan_timeline,
        state.dep_type_map,
        state.package_outdated_counts,
        state.package_latest_info,
        project_id,
        project_name,
        type_counter=state.type_counter,
        # Buffer holds events oldest -> newest (insertion order); reverse for newest-first.
        recent_events=list(state.recent_events_buffer)[::-1],
        upstream=upstream,
    )


async def _maybe_fetch_upstream_cadence(
    release_fetcher: Optional[ReleaseHistoryFetcher],
    package_purls: Dict[str, str],
    first_seen_versions: Dict[Tuple[str, str], datetime],
) -> Optional[UpstreamCadenceMetrics]:
    """Resolve packages via PURLs, call the fetcher, compute aggregate cadence.

    Returns None when no fetcher is configured. Failures inside the fetcher
    are swallowed so that the rest of the report still ships — upstream
    cadence is supplementary, not load-bearing.
    """
    if release_fetcher is None:
        return None

    package_specs: List[Tuple[str, str]] = []
    seen: set = set()
    for name, purl in package_purls.items():
        parsed = parse_purl(purl)
        if parsed is None or not parsed.registry_system:
            continue
        spec = (parsed.registry_system, name)
        if spec in seen:
            continue
        seen.add(spec)
        package_specs.append(spec)

    if not package_specs:
        return None

    try:
        history = await release_fetcher.fetch(package_specs)
    except Exception:
        logger.warning("release-history fetcher failed; skipping upstream cadence", exc_info=True)
        return None

    observations: List[Observation] = [
        (pkg, version, scan_date) for (pkg, version), scan_date in first_seen_versions.items()
    ]
    return aggregate_upstream_metrics(history, observations=observations)


async def compute_update_frequency_comparison(
    projects: List[Dict[str, Any]],
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    max_scans: int = 10,
    since: Optional[datetime] = None,
    release_fetcher: Optional[ReleaseHistoryFetcher] = None,
) -> UpdateFrequencyComparison:
    """
    Compute update frequency comparison across multiple projects.

    At most _COMPARISON_CONCURRENCY concurrent per-project computations run at
    once to avoid saturating MongoDB with simultaneous large queries. Pass
    ``since`` to align all projects on the same calendar window — without it,
    different projects may end up analysed over different time spans
    depending on their scan cadence.
    """
    semaphore = _get_comparison_semaphore()

    async def _compute_single(project: Dict[str, Any]) -> Optional[ProjectUpdateSummary]:
        project_id = project.get("_id") or project.get("id", "")
        project_name = project.get("name", "")
        team_name = project.get("team_name")

        async with semaphore:
            try:
                metrics = await compute_update_frequency(
                    project_id=project_id,
                    project_name=project_name,
                    scan_repo=scan_repo,
                    dep_repo=dep_repo,
                    analysis_repo=analysis_repo,
                    max_scans=max_scans,
                    since=since,
                    release_fetcher=release_fetcher,
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
                dominant_ecosystem=metrics.dominant_ecosystem,
            )

    results = await asyncio.gather(*[_compute_single(p) for p in projects], return_exceptions=True)
    summaries: List[ProjectUpdateSummary] = [s for s in results if isinstance(s, ProjectUpdateSummary)]

    # Sort by coverage desc (None == "perfect / nothing to resolve" → top), then by updates_per_month desc.
    # Treat None as +inf so projects with no outdated history rank above ones with measured coverage.
    def _coverage_key(s: ProjectUpdateSummary) -> float:
        return float("inf") if s.update_coverage_pct is None else s.update_coverage_pct

    summaries.sort(key=lambda s: (_coverage_key(s), s.updates_per_month), reverse=True)

    if summaries:
        avg_updates = sum(s.updates_per_month for s in summaries) / len(summaries)
        coverage_values = [s.update_coverage_pct for s in summaries if s.update_coverage_pct is not None]
        avg_coverage = sum(coverage_values) / len(coverage_values) if coverage_values else 0.0
        best = summaries[0].project_name
        worst = summaries[-1].project_name
    else:
        avg_updates = 0.0
        avg_coverage = 0.0
        best = None
        worst = None

    best_per_ecosystem, worst_per_ecosystem = _per_ecosystem_winners(summaries)

    return UpdateFrequencyComparison(
        projects=summaries,
        team_avg_updates_per_month=round(avg_updates, 2),
        team_avg_coverage_pct=round(avg_coverage, 1),
        best_project=best,
        worst_project=worst,
        best_per_ecosystem=best_per_ecosystem,
        worst_per_ecosystem=worst_per_ecosystem,
    )


def _per_ecosystem_winners(
    summaries: List[ProjectUpdateSummary],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Group summaries by dominant_ecosystem and return per-ecosystem
    best/worst project names. The "mixed" bucket and unclassified projects
    are skipped — for those the global ranking is the only fair option.

    The summaries list is already sorted globally; per-ecosystem ordering
    falls out by walking the list once.
    """
    best: Dict[str, str] = {}
    worst: Dict[str, str] = {}
    for s in summaries:
        eco = s.dominant_ecosystem
        if not eco or eco == "mixed":
            continue
        if eco not in best:
            best[eco] = s.project_name
        worst[eco] = s.project_name  # last wins -> worst (summaries sorted desc)
    return best, worst
