"""Update-frequency analytics: compare dependency versions across scans.

Streaming model — one scan pair at a time so peak memory stays at
~2×deps/scan regardless of project size.
"""

import asyncio
import logging
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

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

# asyncio.Semaphore binds to the running loop on first use. Creating it per
# call (inside compute_update_frequency_comparison) keeps it tied to the loop
# actually running the gather, so reuse across event loops (e.g. successive
# pytest-asyncio tests) can't raise "bound to a different event loop".
_COMPARISON_CONCURRENCY = 3

_DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "purl": 1, "scan_id": 1}


def _release_tuple(version: Version) -> tuple[int, int]:
    """``(major, minor)`` padded with zeros for shorter release tuples."""
    release = version.release
    return (
        release[0] if len(release) > 0 else 0,
        release[1] if len(release) > 1 else 0,
    )


def classify_version_change(old_version: str, new_version: str) -> str:
    """Classify a version change via PEP 440 parsing.

    Returns ``"major" | "minor" | "patch" | "downgrade" | "none" | "unknown"``.
    Any backwards move is ``"downgrade"`` regardless of distance, so rollbacks
    are never counted as update activity. Same release tuple with differing
    pre/post/local segments collapses to ``"patch"`` since the smallest
    meaningful tier still applies.
    """
    try:
        old_v = Version(old_version)
        new_v = Version(new_version)
    except InvalidVersion:
        return "unknown"

    if old_v == new_v:
        return "none"
    if new_v < old_v:
        return "downgrade"
    if new_v.epoch != old_v.epoch:
        return "major"

    old_major, old_minor = _release_tuple(old_v)
    new_major, new_minor = _release_tuple(new_v)

    if new_major != old_major:
        return "major"
    if new_minor != old_minor:
        return "minor"
    return "patch"


def _dep_record(dep: dict[str, Any]) -> tuple[str, dict[str, str]] | None:
    """``(identity, info)`` for one dependency document.

    Identity comes from the purl (type + namespace + name) so same-named
    packages across ecosystems/namespaces — and npm names stored without
    their scope — never collide; bare ``name`` stays in the info for joins
    against analyzer results, which are keyed by that name.
    """
    name = dep.get("name", "")
    if not name:
        return None
    purl = dep.get("purl", "")
    parsed = parse_purl(purl) if purl else None
    if parsed:
        # deps_dev_name folds ecosystem naming (Maven group:artifact, npm scope,
        # PEP 503 for PyPI) so the same package keeps one identity across scans
        # even when the purl name casing/separators vary.
        deps_dev_name = parsed.deps_dev_name
        identity = f"{parsed.type}:{deps_dev_name}"
        display = parsed.full_name
        # SBOM component types ("library") say nothing about the ecosystem; the purl type does.
        dep_type = parsed.type
        registry_system = parsed.registry_system or ""
    else:
        deps_dev_name = ""
        identity = f"{dep.get('type', 'unknown')}::{name}"
        display = name
        dep_type = dep.get("type", "unknown")
        registry_system = ""
    return identity, {
        "version": dep.get("version", ""),
        "type": dep_type,
        "purl": purl,
        "name": name,
        "display": display,
        "registry_system": registry_system,
        "deps_dev_name": deps_dev_name,
    }


def _resolve_duplicate(candidates: list[dict[str, str]]) -> dict[str, str]:
    """Deterministic survivor when one identity appears at several versions in a scan.

    Highest parseable version wins (nested trees usually hoist the newest);
    the tie-break must not depend on Mongo document order, which is unstable
    across scans and would fabricate version changes.
    """
    if len(candidates) == 1:
        return candidates[0]
    parseable: list[tuple[Version, dict[str, str]]] = []
    for cand in candidates:
        try:
            parseable.append((Version(cand["version"]), cand))
        except InvalidVersion:
            continue
    if parseable:
        return max(parseable, key=lambda pair: pair[0])[1]
    return max(candidates, key=lambda cand: cand["version"])


def _pregroup_deps_by_scan(
    all_deps: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, str]]]:
    """Group dependencies by ``scan_id`` into ``{scan_id: {identity: info}}``."""
    candidates: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for dep in all_deps:
        scan_id = dep.get("scan_id", "")
        record = _dep_record(dep)
        if scan_id and record:
            identity, info = record
            candidates[scan_id][identity].append(info)
    return {
        scan_id: {identity: _resolve_duplicate(infos) for identity, infos in per_identity.items()}
        for scan_id, per_identity in candidates.items()
    }


# One outdated_packages row is stored per SBOM of a scan; well above any real SBOM count.
_MAX_OUTDATED_RESULTS_PER_SCAN = 50


async def _load_outdated_for_scan(
    analysis_repo: AnalysisResultRepository,
    scan_id: str,
    package_latest_info: dict[str, dict[str, str]],
) -> set:
    """Union of the scan's outdated_packages results, returning component names.

    Updates ``package_latest_info`` in-place; later writes for the same
    package overwrite earlier ones, which is fine since ``slowest_packages``
    only needs one consistent current/latest pair per name.
    """
    results = await analysis_repo.find_many(
        {"scan_id": scan_id, "analyzer_name": "outdated_packages"},
        limit=_MAX_OUTDATED_RESULTS_PER_SCAN,
    )
    outdated_names: set = set()
    for result in results:
        result_data = getattr(result, "result", {}) or {}
        for entry in result_data.get("outdated_dependencies", []):
            comp = entry.get("component", "")
            if not comp:
                continue
            outdated_names.add(comp)
            package_latest_info[comp] = {
                "current_version": entry.get("current_version", ""),
                "latest_version": entry.get("latest_version", ""),
            }
    return outdated_names


def _compare_scan_pair(
    deps_by_scan: dict[str, dict[str, dict[str, str]]],
    prev_scan_id: str,
    prev_scan_date: datetime,
    curr_scan_id: str,
    curr_scan_date: datetime,
    prev_outdated: set,
) -> list[tuple[DependencyUpdateEvent, str]]:
    """Compare two consecutive scans, returning ``(event, identity)`` pairs."""
    days_between = max(1, (curr_scan_date - prev_scan_date).days)

    prev_deps = deps_by_scan.get(prev_scan_id, {})
    curr_deps = deps_by_scan.get(curr_scan_id, {})

    events: list[tuple[DependencyUpdateEvent, str]] = []
    for identity, curr_info in curr_deps.items():
        prev_info = prev_deps.get(identity)
        if not prev_info or curr_info["version"] == prev_info["version"]:
            continue

        update_type = classify_version_change(prev_info["version"], curr_info["version"])
        if update_type == "none":  # same PEP 440 identity, e.g. v1.0.0 vs 1.0.0
            continue

        events.append(
            (
                DependencyUpdateEvent(
                    package_name=curr_info["display"],
                    package_type=curr_info["type"],
                    purl=curr_info["purl"] or None,
                    old_version=prev_info["version"],
                    new_version=curr_info["version"],
                    update_type=update_type,
                    scan_date=curr_scan_date.isoformat(),
                    previous_scan_date=prev_scan_date.isoformat(),
                    days_between_scans=days_between,
                    was_outdated=prev_info["name"] in prev_outdated,
                ),
                identity,
            )
        )
    return events


def _build_timeline_entry(
    scan_id: str,
    scan_date: datetime,
    events: list[DependencyUpdateEvent],
    outdated_count: int,
) -> ScanTimelineEntry:
    """Build a timeline entry from a list of update events for a scan."""
    type_counts = Counter(e.update_type for e in events)
    downgrades = type_counts.get("downgrade", 0)
    return ScanTimelineEntry(
        scan_id=scan_id,
        date=scan_date.isoformat(),
        updates_count=len(events) - downgrades,
        outdated_count=outdated_count,
        patch=type_counts.get("patch", 0),
        minor=type_counts.get("minor", 0),
        major=type_counts.get("major", 0),
        unknown=type_counts.get("unknown", 0),
        downgrades=downgrades,
    )


def _compute_trend(
    scan_timeline: list[ScanTimelineEntry],
) -> tuple[str, str]:
    """Trend ``(direction, detail)`` from comparing the first vs second half of the timeline.

    The leading baseline entry (no predecessor, structurally zero updates)
    is excluded — averaging it in would report "improving" for every
    project with a steady update rate.
    """
    timeline = scan_timeline[1:]
    if len(timeline) < 4:
        return "unknown", "Not enough scans to determine trend (need at least 5)"

    mid = len(timeline) // 2
    older = timeline[:mid]
    newer = timeline[mid:]

    older_avg_updates = sum(s.updates_count for s in older) / len(older)
    newer_avg_updates = sum(s.updates_count for s in newer) / len(newer)
    older_avg_outdated = sum(s.outdated_count for s in older) / len(older)
    newer_avg_outdated = sum(s.outdated_count for s in newer) / len(newer)

    update_improving = newer_avg_updates > older_avg_updates * 1.1
    outdated_improving = newer_avg_outdated < older_avg_outdated * 0.9
    update_deteriorating = newer_avg_updates < older_avg_updates * 0.9
    outdated_deteriorating = newer_avg_outdated > older_avg_outdated * 1.1

    updates_msg = f"Updates/scan: {older_avg_updates:.1f} → {newer_avg_updates:.1f}"
    outdated_msg = f"Outdated: {older_avg_outdated:.1f} → {newer_avg_outdated:.1f}"
    improving_parts = [m for m, ok in ((updates_msg, update_improving), (outdated_msg, outdated_improving)) if ok]
    deteriorating_parts = [
        m for m, ok in ((updates_msg, update_deteriorating), (outdated_msg, outdated_deteriorating)) if ok
    ]

    if improving_parts and deteriorating_parts:
        return "stable", f"Mixed signals. {'. '.join(improving_parts + deteriorating_parts)}"
    if improving_parts:
        return "improving", ". ".join(improving_parts)
    if deteriorating_parts:
        return "deteriorating", ". ".join(deteriorating_parts)

    return "stable", (f"Consistent (~{newer_avg_updates:.1f} updates/scan, ~{newer_avg_outdated:.0f} outdated)")


def _granularity_ratio(type_counter: Counter, total_updates: int) -> dict[str, float]:
    """Per-update-type share of all updates, rounded to 2 dp."""
    if not total_updates:
        return {"patch": 0.0, "minor": 0.0, "major": 0.0, "unknown": 0.0}
    return {
        bucket: round(type_counter.get(bucket, 0) / total_updates, 2)
        for bucket in ("patch", "minor", "major", "unknown")
    }


def _aggregate_metrics(
    completed_scans: list[dict[str, Any]],
    ever_outdated: set,
    ever_resolved: set,
    scan_timeline: list[ScanTimelineEntry],
    dep_type_map: dict[str, str],
    package_outdated_counts: dict[str, int],
    package_latest_info: dict[str, dict[str, str]],
    project_id: str,
    project_name: str,
    *,
    type_counter: Counter,
    recent_events: list[DependencyUpdateEvent],
    upstream: UpstreamCadenceMetrics | None = None,
    branch: str | None = None,
    final_outdated: set | None = None,
    final_versions: dict[str, str] | None = None,
) -> UpdateFrequencyMetrics:
    """Build the final metrics response from streamed counters."""
    downgrade_total = type_counter.get("downgrade", 0)
    # Downgrades are recorded but are not update activity.
    total_updates = sum(type_counter.values()) - downgrade_total
    num_intervals = len(completed_scans) - 1

    first_date: datetime = completed_scans[0]["created_at"]
    last_date: datetime = completed_scans[-1]["created_at"]
    raw_range_days = (last_date - first_date).total_seconds() / 86400.0
    # Floored at one day so a single CI burst can't explode the monthly rate.
    time_range_days = max(1.0, raw_range_days)
    time_range_months = time_range_days / 30.44

    patch_total = type_counter.get("patch", 0)
    minor_total = type_counter.get("minor", 0)
    major_total = type_counter.get("major", 0)
    unknown_total = type_counter.get("unknown", 0)

    granularity_ratio = _granularity_ratio(type_counter, total_updates)
    # Cadence reports the real average interval, not the floored range.
    avg_days_between = raw_range_days / num_intervals if num_intervals else 0

    total_outdated_detected = len(ever_outdated)
    outdated_resolved_count = len(ever_outdated & ever_resolved)
    # None means "nothing was ever outdated" — distinct from 0.0 ("nothing resolved").
    update_coverage_pct: float | None = (
        round(outdated_resolved_count / total_outdated_detected * 100, 1) if total_outdated_detected else None
    )

    trend_direction, trend_detail = _compute_trend(scan_timeline)

    slowest_packages = _build_slowest_packages(
        package_outdated_counts,
        package_latest_info,
        dep_type_map,
        final_outdated or set(),
        final_versions or {},
    )

    return UpdateFrequencyMetrics(
        project_id=project_id,
        project_name=project_name,
        branch=branch,
        scan_count=len(completed_scans),
        time_range_days=round(time_range_days, 2),
        first_scan_date=first_date.isoformat(),
        last_scan_date=last_date.isoformat(),
        total_updates=total_updates,
        updates_per_scan=round(total_updates / num_intervals, 2) if num_intervals else 0,
        updates_per_month=round(total_updates / time_range_months, 2) if time_range_months else 0,
        patch_updates=patch_total,
        minor_updates=minor_total,
        major_updates=major_total,
        unknown_updates=unknown_total,
        downgrade_updates=downgrade_total,
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
        upstream_releases_last_12m_median=(upstream.upstream_releases_last_12m_median if upstream else None),
        upstream_days_between_releases_median=(upstream.upstream_days_between_releases_median if upstream else None),
        upstream_days_since_latest_release_median=(
            upstream.upstream_days_since_latest_release_median if upstream else None
        ),
        adoption_latency_days_median=(upstream.adoption_latency_days_median if upstream else None),
        dominant_ecosystem=_dominant_ecosystem(dep_type_map),
    )


def _final_versions_by_name(final_deps: dict[str, dict[str, str]]) -> dict[str, str]:
    """Newest-scan version per bare name, only where the name is unambiguous.

    The outdated analyzer keys by bare name, but two purl identities can
    share one name (npm scopes are dropped in storage). Mapping such a name
    to a single version would show one sibling's version for the other, so
    ambiguous names are omitted and the analyzer's own current_version stands.
    """
    counts: Counter = Counter(info["name"] for info in final_deps.values())
    return {info["name"]: info["version"] for info in final_deps.values() if counts[info["name"]] == 1}


def _build_slowest_packages(
    package_outdated_counts: dict[str, int],
    package_latest_info: dict[str, dict[str, str]],
    dep_type_map: dict[str, str],
    final_outdated: set,
    final_versions: dict[str, str],
) -> list[SlowPackage]:
    """Slowest-to-update packages: the remaining backlog, ranked by scans outdated.

    Only packages still outdated in the newest scan qualify — resolved ones
    are history, not backlog. ``current_version`` comes from the newest
    scan's dependency set; analyzer entries may be scans old.
    """
    remaining = {pkg: count for pkg, count in package_outdated_counts.items() if pkg in final_outdated}
    slowest = sorted(remaining.items(), key=lambda x: x[1], reverse=True)[:15]
    return [
        SlowPackage(
            name=pkg_name,
            type=dep_type_map.get(pkg_name, "unknown"),
            current_version=final_versions.get(pkg_name)
            or package_latest_info.get(pkg_name, {}).get("current_version"),
            latest_version=package_latest_info.get(pkg_name, {}).get("latest_version"),
            scans_outdated=count,
        )
        for pkg_name, count in slowest
    ]


def _empty_metrics(
    project_id: str,
    project_name: str,
    scan_count: int,
    scan_date: str,
    branch: str | None = None,
) -> UpdateFrequencyMetrics:
    """Return empty metrics when there are fewer than 2 scans."""
    return UpdateFrequencyMetrics(
        project_id=project_id,
        project_name=project_name,
        branch=branch,
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

# Bounds the (package, version) -> first_scan_date map used for adoption-latency.
# Far above realistic projects; protects against pathological version churn.
_MAX_OBSERVATIONS = 10_000

_ECOSYSTEM_DOMINANCE_THRESHOLD = 0.7


def _dominant_ecosystem(dep_type_map: dict[str, str]) -> str | None:
    """Ecosystem owning ≥70% of classified deps; ``"mixed"`` otherwise; ``None`` if empty.

    Excludes ``"unknown"`` so missing-PURL noise doesn't tilt the result.
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
    """Streaming-loop state, bundled so each helper takes a single argument."""

    type_counter: Counter = field(default_factory=Counter)
    recent_events_buffer: deque[DependencyUpdateEvent] = field(
        default_factory=lambda: deque(maxlen=_RECENT_EVENTS_BUFFER_SIZE)
    )
    scan_timeline: list[ScanTimelineEntry] = field(default_factory=list)
    package_outdated_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    package_latest_info: dict[str, dict[str, str]] = field(default_factory=dict)
    dep_type_map: dict[str, str] = field(default_factory=dict)
    ever_outdated: set = field(default_factory=set)
    ever_resolved: set = field(default_factory=set)
    first_seen_versions: dict[tuple[str, str], datetime] = field(default_factory=dict)
    # identity -> (deps.dev system, deps_dev_name); deps.dev keys by deps_dev_name, not the bare DB name.
    package_specs: dict[str, tuple[str, str]] = field(default_factory=dict)

    def accumulate_types(self, deps: dict[str, dict[str, str]]) -> None:
        for identity, info in deps.items():
            name = info["name"]
            if name not in self.dep_type_map:
                self.dep_type_map[name] = info["type"]
            system = info["registry_system"]
            if system and identity not in self.package_specs:
                self.package_specs[identity] = (system, info["deps_dev_name"])

    def record_outdated(self, outdated: set) -> None:
        for pkg in outdated:
            self.package_outdated_counts[pkg] += 1
            self.ever_outdated.add(pkg)

    def record_resolved(self, prev_outdated: set, curr_outdated: set, curr_deps: dict[str, dict[str, str]]) -> None:
        """Resolved = still present but no longer flagged outdated.

        A version bump that stays behind latest is not a resolution, and
        neither is removing the package.
        """
        curr_names = {info["name"] for info in curr_deps.values()}
        for pkg in prev_outdated:
            if pkg in curr_names and pkg not in curr_outdated:
                self.ever_resolved.add(pkg)

    def absorb_events(self, events: list[tuple[DependencyUpdateEvent, str]], curr_scan_date: datetime) -> None:
        for e, identity in events:
            self.type_counter[e.update_type] += 1
            self.recent_events_buffer.append(e)
            if len(self.first_seen_versions) < _MAX_OBSERVATIONS:
                key = (identity, e.new_version)
                if key not in self.first_seen_versions:
                    self.first_seen_versions[key] = curr_scan_date


def _as_utc(dt: datetime) -> datetime:
    """Mongo/Motor returns naive UTC datetimes; make them aware once at load."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def _branch_scan_count(scan_repo: ScanRepository, project_id: str, branch: str) -> int:
    scans = await scan_repo.find_many(
        {"project_id": project_id, "status": "completed", "branch": branch, "is_rescan": {"$ne": True}},
        limit=2,
        projection={"_id": 1},
    )
    return len(scans)


async def _resolve_primary_branch(
    scan_repo: ScanRepository,
    project_id: str,
    deleted_branches: list[str] | None,
    default_branch: str | None,
) -> str | None:
    """Branch to analyze when the caller names none.

    The project's configured ``default_branch`` wins when it has enough
    history to compute anything; only then do we fall back to the newest
    scanned live branch, so a one-off scan on a feature branch can't hijack
    the analysis.
    """
    deleted = deleted_branches or []
    if (
        default_branch
        and default_branch not in deleted
        and await _branch_scan_count(scan_repo, project_id, default_branch) >= 2
    ):
        return default_branch

    query: dict[str, Any] = {"project_id": project_id, "status": "completed", "is_rescan": {"$ne": True}}
    if deleted:
        query["branch"] = {"$nin": list(deleted)}
    doc = await scan_repo.find_one(query, sort=[("created_at", -1), ("_id", -1)])
    return doc.get("branch") if doc else None


def _collapse_same_commit_runs(scans_raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only the first scan of each consecutive same-commit run.

    CI retries and duplicate ingests produce bursts of scans for one commit;
    they carry identical SBOMs, so extra entries only pad the timeline with
    zero-update bars and compress the covered time range.
    """
    collapsed: list[dict[str, Any]] = []
    for scan in scans_raw:
        prev = collapsed[-1] if collapsed else None
        if prev is not None and scan["commit_hash"] and prev["commit_hash"] == scan["commit_hash"]:
            continue
        collapsed.append(scan)
    return collapsed


# Same-commit collapse can shrink the fetched set; over-fetch so a burst of
# CI retries on the head commit can't starve the window below max_scans.
_COLLAPSE_HEADROOM = 5


async def _load_completed_scans(
    scan_repo: ScanRepository,
    project_id: str,
    branch: str,
    max_scans: int,
    since: datetime | None,
    hard_limit: int,
) -> list[dict[str, Any]]:
    """Completed non-rescan scans of one branch, chronologically ordered.

    When ``since`` is set the calendar window dominates (capped by
    ``hard_limit``) and ``max_scans`` is ignored.
    """
    fetch_limit = hard_limit if since is not None else min(hard_limit, max_scans * _COLLAPSE_HEADROOM)
    # Filter status in the query so the limit counts only completed scans; filtering after
    # the limit would empty the window when the newest scans are failed/processing.
    # find_many returns Scan models, so project the fields Scan requires (project_id, branch).
    scans = await scan_repo.find_many(
        {"project_id": project_id, "status": "completed", "branch": branch, "is_rescan": {"$ne": True}},
        sort=[("created_at", -1), ("_id", -1)],
        limit=fetch_limit,
        projection={"_id": 1, "created_at": 1, "status": 1, "project_id": 1, "branch": 1, "commit_hash": 1},
    )
    scans_raw: list[dict[str, Any]] = [
        {"_id": s.id, "created_at": _as_utc(s.created_at), "status": s.status, "commit_hash": s.commit_hash}
        for s in scans
    ]
    if since is not None:
        scans_raw = [s for s in scans_raw if s["created_at"] >= since]
    scans_raw.reverse()
    collapsed = _collapse_same_commit_runs(scans_raw)
    # Collapse first, THEN cap, so distinct commits fill the window even after a storm.
    if since is None and len(collapsed) > max_scans:
        collapsed = collapsed[-max_scans:]
    return collapsed


async def compute_update_frequency(
    project_id: str,
    project_name: str,
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    max_scans: int = 20,
    since: datetime | None = None,
    release_fetcher: ReleaseHistoryFetcher | None = None,
    hard_limit: int = _DEFAULT_HARD_LIMIT,
    branch: str | None = None,
    deleted_branches: list[str] | None = None,
    default_branch: str | None = None,
) -> UpdateFrequencyMetrics:
    """Compute update-frequency metrics for one project on one branch.

    ``branch`` defaults to the project's ``default_branch`` (if scanned),
    else the branch of the newest completed non-rescan scan; comparing
    across branches would count branch differences as updates. With
    ``since`` set, all scans newer than the cutoff are analysed (up to
    ``hard_limit``). Otherwise the newest ``max_scans`` are taken.
    """
    analyzed_branch = branch or await _resolve_primary_branch(scan_repo, project_id, deleted_branches, default_branch)
    if analyzed_branch is None:
        return _empty_metrics(project_id, project_name, 0, "", branch=None)

    completed_scans = await _load_completed_scans(scan_repo, project_id, analyzed_branch, max_scans, since, hard_limit)

    if len(completed_scans) < 2:
        first_date_str = completed_scans[0]["created_at"].isoformat() if completed_scans else ""
        return _empty_metrics(project_id, project_name, len(completed_scans), first_date_str, branch=analyzed_branch)

    state = _AccumulatorState()

    async def _load_scan_deps(scan_id: str) -> dict[str, dict[str, str]]:
        docs = await dep_repo.find_all({"scan_id": scan_id}, projection=_DEP_PROJECTION)
        return _pregroup_deps_by_scan(docs).get(scan_id, {})

    first_scan = completed_scans[0]
    prev_deps = await _load_scan_deps(first_scan["_id"])
    state.accumulate_types(prev_deps)
    prev_outdated = await _load_outdated_for_scan(analysis_repo, first_scan["_id"], state.package_latest_info)
    state.record_outdated(prev_outdated)
    state.scan_timeline.append(
        _build_timeline_entry(first_scan["_id"], first_scan["created_at"], [], len(prev_outdated))
    )

    for i in range(1, len(completed_scans)):
        prev_scan = completed_scans[i - 1]
        curr_scan = completed_scans[i]

        curr_deps = await _load_scan_deps(curr_scan["_id"])
        state.accumulate_types(curr_deps)

        curr_outdated = await _load_outdated_for_scan(analysis_repo, curr_scan["_id"], state.package_latest_info)
        state.record_outdated(curr_outdated)
        state.record_resolved(prev_outdated, curr_outdated, curr_deps)

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
            _build_timeline_entry(curr_scan["_id"], curr_scan["created_at"], [e for e, _ in events], len(curr_outdated))
        )

        prev_deps = curr_deps
        prev_outdated = curr_outdated

    upstream = await _maybe_fetch_upstream_cadence(release_fetcher, state.package_specs, state.first_seen_versions)

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
        recent_events=list(state.recent_events_buffer)[::-1],  # newest first
        upstream=upstream,
        branch=analyzed_branch,
        final_outdated=prev_outdated,
        final_versions=_final_versions_by_name(prev_deps),
    )


async def _maybe_fetch_upstream_cadence(
    release_fetcher: ReleaseHistoryFetcher | None,
    package_specs: dict[str, tuple[str, str]],
    first_seen_versions: dict[tuple[str, str], datetime],
) -> UpstreamCadenceMetrics | None:
    """Call the fetcher and aggregate cadence; supplementary, never load-bearing.

    Failures and a missing fetcher both yield ``None`` so the rest of the
    report still ships.
    """
    if release_fetcher is None or not package_specs:
        return None

    try:
        history = await release_fetcher.fetch(list(dict.fromkeys(package_specs.values())))
    except Exception:
        logger.warning("release-history fetcher failed; skipping upstream cadence", exc_info=True)
        return None

    observations: list[Observation] = []
    for (identity, version), scan_date in first_seen_versions.items():
        spec = package_specs.get(identity)
        if spec is None:
            continue
        system, registry_name = spec
        observations.append((system, registry_name, version, scan_date))
    return aggregate_upstream_metrics(history, observations=observations)


async def compute_update_frequency_comparison(
    projects: list[dict[str, Any]],
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    max_scans: int = 10,
    since: datetime | None = None,
    release_fetcher: ReleaseHistoryFetcher | None = None,
) -> UpdateFrequencyComparison:
    """Cross-project update-frequency ranking.

    Per-project computations run with bounded concurrency. Pass ``since``
    to align projects on the same calendar window; otherwise scan-cadence
    differences make the comparison apples-to-oranges.
    """
    # Created per call so it binds to the loop running this gather (see note
    # at module top); a module-global semaphore would pin to the first loop.
    semaphore = asyncio.Semaphore(_COMPARISON_CONCURRENCY)

    async def _compute_single(project: dict[str, Any]) -> ProjectUpdateSummary | None:
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
                    deleted_branches=project.get("deleted_branches"),
                    default_branch=project.get("default_branch"),
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
    summaries: list[ProjectUpdateSummary] = [s for s in results if isinstance(s, ProjectUpdateSummary)]

    # None coverage means "nothing was ever outdated" — no measurement, so those
    # projects rank after every measured one and never become best or worst.
    measured = [s for s in summaries if s.update_coverage_pct is not None]
    unmeasured = [s for s in summaries if s.update_coverage_pct is None]
    measured.sort(key=lambda s: (s.update_coverage_pct, s.updates_per_month), reverse=True)
    unmeasured.sort(key=lambda s: s.updates_per_month, reverse=True)
    summaries = measured + unmeasured

    avg_updates = sum(s.updates_per_month for s in summaries) / len(summaries) if summaries else 0.0
    avg_coverage = (
        round(sum(s.update_coverage_pct for s in measured) / len(measured), 1)  # type: ignore[misc]
        if measured
        else None
    )
    best = measured[0].project_name if measured else None
    worst = measured[-1].project_name if len(measured) >= 2 else None

    return UpdateFrequencyComparison(
        projects=summaries,
        team_avg_updates_per_month=round(avg_updates, 2),
        team_avg_coverage_pct=avg_coverage,
        best_project=best,
        worst_project=worst,
        skipped_projects=len(projects) - len(summaries),
    )
