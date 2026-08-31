"""Update-frequency analytics: compare dependency versions across scans.

Streaming model — one scan pair at a time so peak memory stays at
~2×deps/scan regardless of project size.
"""

import asyncio
import logging
from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

from app.core.constants import SCAN_USABLE_STATUSES
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    WINDOW_HARD_LIMIT,
    BranchWindowActivity,
    window_scans_by_branch,
)
from app.schemas.analytics import (
    DependencyUpdateEvent,
    ProjectUpdateSummary,
    ScanTimelineEntry,
    SlowPackage,
    UpdateDataStatus,
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

DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "purl": 1}

DAYS_PER_MONTH = 30.44


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


def fold_scan_deps(deps: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Fold one scan's dependency documents into ``{identity: info}``."""
    candidates: dict[str, list[dict[str, str]]] = defaultdict(list)
    for dep in deps:
        record = _dep_record(dep)
        if record:
            identity, info = record
            candidates[identity].append(info)
    return {identity: _resolve_duplicate(infos) for identity, infos in candidates.items()}


# One outdated_packages row is stored per SBOM of a scan; well above any real SBOM count.
_MAX_OUTDATED_RESULTS_PER_SCAN = 50


async def load_outdated_entries(
    analysis_repo: AnalysisResultRepository,
    scan_id: str,
    projection: dict[str, int] | None = None,
) -> list[dict[str, Any]] | None:
    """The scan's ``outdated_dependencies`` entries, or None when it carries no such analysis.

    An analyzer that raised leaves no document behind and one that failed stores a
    result without ``outdated_dependencies``; reading either as an empty backlog
    would report the whole backlog of the previous scan as brought up to date.
    """
    docs = await analysis_repo.find_many_raw(
        {"scan_id": scan_id, "analyzer_name": "outdated_packages"},
        limit=_MAX_OUTDATED_RESULTS_PER_SCAN,
        projection=projection,
    )
    entries: list[dict[str, Any]] = []
    measured = False
    for doc in docs:
        found = (doc.get("result") or {}).get("outdated_dependencies")
        if not isinstance(found, list):
            continue
        measured = True
        entries.extend(found)
    return entries if measured else None


async def _load_outdated_for_scan(
    analysis_repo: AnalysisResultRepository,
    scan_id: str,
    package_latest_info: dict[str, dict[str, str]],
) -> set[str] | None:
    """Component names the scan flagged as outdated, or None when it carries no such analysis.

    Updates ``package_latest_info`` in-place; later writes for the same
    package overwrite earlier ones, which is fine since ``slowest_packages``
    only needs one consistent current/latest pair per name.
    """
    entries = await load_outdated_entries(analysis_repo, scan_id)
    if entries is None:
        return None
    outdated_names: set[str] = set()
    for entry in entries:
        comp = entry.get("component", "")
        if not comp:
            continue
        outdated_names.add(comp)
        package_latest_info[comp] = {
            "current_version": entry.get("current_version", ""),
            "latest_version": entry.get("latest_version", ""),
        }
    return outdated_names


def _measured_count(outdated: set[str] | None) -> int | None:
    return None if outdated is None else len(outdated)


def _compare_scan_pair(
    deps_by_scan: dict[str, dict[str, dict[str, str]]],
    prev_scan_id: str,
    prev_scan_date: datetime,
    curr_scan_id: str,
    curr_scan_date: datetime,
    prev_outdated: set[str] | None,
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
                    was_outdated=prev_info["name"] in (prev_outdated or ()),
                ),
                identity,
            )
        )
    return events


def _build_timeline_entry(
    scan_id: str,
    scan_date: datetime,
    events: list[DependencyUpdateEvent],
    outdated_count: int | None,
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


def _mean_outdated(entries: Sequence[ScanTimelineEntry]) -> float | None:
    """Mean backlog over the scans that carried an outdated analysis, or None if none did."""
    measured = [s.outdated_count for s in entries if s.outdated_count is not None]
    if not measured:
        return None
    return sum(measured) / len(measured)


def compute_trend(scan_timeline: Sequence[ScanTimelineEntry]) -> tuple[str, str]:
    """Trend ``(direction, detail)`` from comparing the first vs second half of the timeline.

    The leading baseline entry (no predecessor, structurally zero updates)
    is excluded — averaging it in would report "improving" for every
    project with a steady update rate. The backlog signal is dropped when
    either half has no outdated analysis, since a missing measurement is
    not a backlog of zero.
    """
    timeline = scan_timeline[1:]
    if len(timeline) < 4:
        return "unknown", "Not enough scans to determine trend (need at least 5)"

    mid = len(timeline) // 2
    older = timeline[:mid]
    newer = timeline[mid:]

    older_avg_updates = sum(s.updates_count for s in older) / len(older)
    newer_avg_updates = sum(s.updates_count for s in newer) / len(newer)
    older_avg_outdated = _mean_outdated(older)
    newer_avg_outdated = _mean_outdated(newer)

    update_improving = newer_avg_updates > older_avg_updates * 1.1
    update_deteriorating = newer_avg_updates < older_avg_updates * 0.9
    updates_msg = f"Updates/scan: {older_avg_updates:.1f} → {newer_avg_updates:.1f}"
    signals = [(updates_msg, update_improving, update_deteriorating)]

    if older_avg_outdated is not None and newer_avg_outdated is not None:
        outdated_msg = f"Outdated: {older_avg_outdated:.1f} → {newer_avg_outdated:.1f}"
        signals.append(
            (
                outdated_msg,
                newer_avg_outdated < older_avg_outdated * 0.9,
                newer_avg_outdated > older_avg_outdated * 1.1,
            )
        )

    improving_parts = [msg for msg, improving, _ in signals if improving]
    deteriorating_parts = [msg for msg, _, deteriorating in signals if deteriorating]

    if improving_parts and deteriorating_parts:
        return "stable", f"Mixed signals. {'. '.join(improving_parts + deteriorating_parts)}"
    if improving_parts:
        return "improving", ". ".join(improving_parts)
    if deteriorating_parts:
        return "deteriorating", ". ".join(deteriorating_parts)

    steady = f"Consistent (~{newer_avg_updates:.1f} updates/scan"
    if newer_avg_outdated is None:
        return "stable", f"{steady})"
    return "stable", f"{steady}, ~{newer_avg_outdated:.0f} outdated)"


def granularity_ratio(type_counter: Counter, total_updates: int) -> dict[str, float]:
    """Per-update-type share of all updates, rounded to 2 dp."""
    if not total_updates:
        return {"patch": 0.0, "minor": 0.0, "major": 0.0, "unknown": 0.0}
    return {
        bucket: round(type_counter.get(bucket, 0) / total_updates, 2)
        for bucket in ("patch", "minor", "major", "unknown")
    }


def window_cutoff(window_days: int | None) -> datetime | None:
    """UTC timestamp ``window_days`` back, or None when no calendar window was selected."""
    if window_days is None:
        return None
    return datetime.now(tz=timezone.utc) - timedelta(days=window_days)


def updates_per_month(total_updates: int, window_days: int | None) -> float | None:
    """Monthly update rate over the selected calendar window, or None without one.

    Deriving the denominator from the observed scan span instead would make the
    number mean something different for every CI cadence — a project scanning
    twice an hour would outrank a weekly one on the same activity — and this is
    the ranking's primary sort key.
    """
    if window_days is None:
        return None
    return round(total_updates / (window_days / DAYS_PER_MONTH), 2)


def _aggregate_metrics(
    completed_scans: list[dict[str, Any]],
    ever_outdated: set[str],
    ever_resolved: set[str],
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
    latest_outdated: set[str] | None = None,
    final_versions: dict[str, str] | None = None,
    window_days: int | None = None,
) -> UpdateFrequencyMetrics:
    """Build the final metrics response from streamed counters."""
    downgrade_total = type_counter.get("downgrade", 0)
    # Downgrades are recorded but are not update activity.
    total_updates = sum(type_counter.values()) - downgrade_total
    num_intervals = len(completed_scans) - 1

    first_date: datetime = completed_scans[0]["created_at"]
    last_date: datetime = completed_scans[-1]["created_at"]
    raw_range_days = (last_date - first_date).total_seconds() / 86400.0
    # Floored at one day so the rendered span never reads as zero.
    time_range_days = max(1.0, raw_range_days)

    patch_total = type_counter.get("patch", 0)
    minor_total = type_counter.get("minor", 0)
    major_total = type_counter.get("major", 0)
    unknown_total = type_counter.get("unknown", 0)

    ratio = granularity_ratio(type_counter, total_updates)
    # Cadence reports the real average interval, not the floored range.
    avg_days_between = raw_range_days / num_intervals if num_intervals else 0

    total_outdated_detected = len(ever_outdated)
    outdated_resolved_count = len(ever_outdated & ever_resolved)
    # Both sets carry measured scans only, so None means "no backlog was ever
    # measured here" — distinct from 0.0 ("measured, nothing resolved").
    update_coverage_pct: float | None = (
        round(outdated_resolved_count / total_outdated_detected * 100, 1) if total_outdated_detected else None
    )

    trend_direction, trend_detail = compute_trend(scan_timeline)

    slowest_packages = _build_slowest_packages(
        package_outdated_counts,
        package_latest_info,
        dep_type_map,
        latest_outdated or set(),
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
        updates_per_month=updates_per_month(total_updates, window_days),
        patch_updates=patch_total,
        minor_updates=minor_total,
        major_updates=major_total,
        unknown_updates=unknown_total,
        downgrade_updates=downgrade_total,
        granularity_ratio=ratio,
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
    latest_outdated: set[str],
    final_versions: dict[str, str],
) -> list[SlowPackage]:
    """Slowest-to-update packages: the remaining backlog, ranked by scans outdated.

    Only packages still outdated in the newest scan that carried an outdated
    analysis qualify — resolved ones are history, not backlog, and a scan
    without the analysis is not a cleared backlog. ``current_version`` comes
    from the newest scan's dependency set; analyzer entries may be scans old.
    """
    remaining = {pkg: count for pkg, count in package_outdated_counts.items() if pkg in latest_outdated}
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
        updates_per_month=None,
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

ECOSYSTEM_DOMINANCE_THRESHOLD = 0.7


def _dominant_ecosystem(dep_type_map: dict[str, str]) -> str | None:
    """Ecosystem owning ≥70% of classified deps; ``"mixed"`` otherwise; ``None`` if empty.

    Excludes ``"unknown"`` so missing-PURL noise doesn't tilt the result.
    """
    classified = [t for t in dep_type_map.values() if t and t != "unknown"]
    if not classified:
        return None
    counts = Counter(classified)
    top_type, top_count = counts.most_common(1)[0]
    if top_count / len(classified) >= ECOSYSTEM_DOMINANCE_THRESHOLD:
        return top_type
    return "mixed"


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
    ever_outdated: set[str] = field(default_factory=set)
    ever_resolved: set[str] = field(default_factory=set)
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

    def record_outdated(self, outdated: set[str] | None) -> None:
        for pkg in outdated or ():
            self.package_outdated_counts[pkg] += 1
            self.ever_outdated.add(pkg)

    def record_resolved(
        self,
        prev_outdated: set[str] | None,
        curr_outdated: set[str] | None,
        curr_deps: dict[str, dict[str, str]],
    ) -> None:
        """Resolved = still present but no longer flagged outdated.

        A version bump that stays behind latest is not a resolution, and
        neither is removing the package. Both scans must carry an outdated
        analysis: a missing one is not an empty backlog, and reading it as
        one would report the predecessor's whole backlog as resolved.
        """
        if prev_outdated is None or curr_outdated is None:
            return
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


def as_utc(dt: datetime) -> datetime:
    """Mongo/Motor returns naive UTC datetimes; make them aware once at load."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


_MIN_COMPARABLE_COMMITS = 2


def select_primary_branch(
    activity: Mapping[str, BranchWindowActivity],
    default_branch: str | None,
    deleted_branches: Sequence[str] | None = None,
) -> str | None:
    """The branch a project's numbers describe, from what each branch was scanned in the window.

    The configured ``default_branch`` wins as soon as it can be compared at all;
    otherwise the busiest branch does, because a one-off scan on a feature
    branch must not hijack a project and most projects configure no default
    branch. Ties go to the branch scanned last, then to its name, so the pick
    never depends on document order.
    """
    deleted = set(deleted_branches or ())
    live = {branch: seen for branch, seen in activity.items() if branch not in deleted}
    if not live:
        return None
    if default_branch in live and live[default_branch].commit_count >= _MIN_COMPARABLE_COMMITS:
        return default_branch
    return max(live, key=lambda branch: (live[branch].commit_count, live[branch].last_scan_at, branch))


# Slack for the scans the ledger reached between the two reads. A missing backfill
# or a broken delta chain loses far more than a fifth of a window.
READY_COVERAGE_RATIO = 0.8


def window_coverage_status(accounted_commits: int, window_commits: int) -> Literal["ready", "partial"]:
    """``partial`` when the ledger accounts for noticeably less than the branch really holds.

    A partial row's numbers are exact for what they cover, but they measure a
    shorter stretch than a fully covered project's, so callers must keep them out
    of averages, best/worst and the ranking. Both arguments count commits of the
    same stretch; a caller that truncated its own stretch to a document cap knows
    no commit count for what it kept and must not ask.
    """
    return "ready" if accounted_commits >= window_commits * READY_COVERAGE_RATIO else "partial"


def collapse_same_commit_runs(scans_raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
) -> tuple[list[dict[str, Any]], bool]:
    """Completed non-rescan scans of one branch, chronologically ordered.

    When ``since`` is set the calendar window dominates (capped by
    ``hard_limit``) and ``max_scans`` is ignored.
    """
    fetch_limit = hard_limit if since is not None else min(hard_limit, max_scans * _COLLAPSE_HEADROOM)
    # Filter status in the query so the limit counts only completed scans; filtering after
    # the limit would empty the window when the newest scans are failed/processing.
    docs = await scan_repo.find_many_raw(
        {
            "project_id": project_id,
            "status": {"$in": SCAN_USABLE_STATUSES},
            "branch": branch,
            "is_rescan": {"$ne": True},
        },
        sort=[("created_at", -1), ("_id", -1)],
        limit=fetch_limit,
        projection={"_id": 1, "created_at": 1, "commit_hash": 1},
    )
    scans_raw: list[dict[str, Any]] = [
        {"_id": d["_id"], "created_at": as_utc(d["created_at"]), "commit_hash": d.get("commit_hash")}
        for d in docs
        # Archive restore inserts bundle JSON verbatim, so a date can arrive as an ISO string.
        # Neither the window aggregation nor the delta writer matches those, so analysing them
        # here would put scans on the timeline that nothing else in the pipeline accounts for.
        if isinstance(d.get("created_at"), datetime)
    ]
    if since is not None:
        scans_raw = [s for s in scans_raw if s["created_at"] >= since]
    scans_raw.reverse()
    collapsed = collapse_same_commit_runs(scans_raw)
    # Collapse first, THEN cap, so distinct commits fill the window even after a storm.
    if since is None and len(collapsed) > max_scans:
        collapsed = collapsed[-max_scans:]
    # A full fetch means older scans of this branch went unread, so the window the caller
    # asked for is wider than the stretch it is about to fold.
    return collapsed, len(docs) >= fetch_limit


def _spanned_days(scans: list[dict[str, Any]]) -> int:
    """Whole days the retained stretch covers, floored at one so a burst cannot inflate a rate."""
    span: timedelta = scans[-1]["created_at"] - scans[0]["created_at"]
    return max(1, round(span.total_seconds() / 86400))


async def compute_update_frequency(
    project_id: str,
    project_name: str,
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    max_scans: int = 20,
    window_days: int | None = None,
    release_fetcher: ReleaseHistoryFetcher | None = None,
    hard_limit: int = WINDOW_HARD_LIMIT,
    branch: str | None = None,
    deleted_branches: list[str] | None = None,
    default_branch: str | None = None,
) -> UpdateFrequencyMetrics:
    """Compute update-frequency metrics for one project on one branch.

    ``branch`` defaults to ``select_primary_branch``'s pick over the same window;
    comparing across branches would count branch differences as updates. With
    ``window_days`` set, all scans of that calendar window are analysed (up
    to ``hard_limit``). Otherwise the newest ``max_scans`` are taken and no
    monthly rate is reported, since there is no shared denominator.
    """
    since = window_cutoff(window_days)
    analyzed_branch = branch
    if analyzed_branch is None:
        activity = await window_scans_by_branch(scan_repo, [project_id], since)
        analyzed_branch = select_primary_branch(
            {seen_branch: seen for (_project_id, seen_branch), seen in activity.items()},
            default_branch,
            deleted_branches,
        )
    if analyzed_branch is None:
        return _empty_metrics(project_id, project_name, 0, "", branch=None)

    completed_scans, truncated = await _load_completed_scans(
        scan_repo, project_id, analyzed_branch, max_scans, since, hard_limit
    )

    state = _AccumulatorState()

    async def _load_scan_deps(scan_id: str) -> dict[str, dict[str, str]]:
        docs = await dep_repo.find_all({"scan_id": scan_id}, projection=DEP_PROJECTION)
        return fold_scan_deps(docs)

    analysed: list[dict[str, Any]] = []
    prev_deps: dict[str, dict[str, str]] = {}
    prev_outdated: set[str] | None = None
    latest_outdated: set[str] | None = None

    for curr_scan in completed_scans:
        curr_deps = await _load_scan_deps(curr_scan["_id"])
        # A scan that produced no SBOM measured nothing, so the delta ledger drops it.
        # Keeping it here would frame the update that happened across it as two quiet
        # intervals and put a structural zero-update bar on the timeline.
        if not curr_deps:
            continue
        state.accumulate_types(curr_deps)

        curr_outdated = await _load_outdated_for_scan(analysis_repo, curr_scan["_id"], state.package_latest_info)
        state.record_outdated(curr_outdated)

        events: list[tuple[DependencyUpdateEvent, str]] = []
        if analysed:
            prev_scan = analysed[-1]
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
            _build_timeline_entry(
                curr_scan["_id"], curr_scan["created_at"], [e for e, _ in events], _measured_count(curr_outdated)
            )
        )

        analysed.append(curr_scan)
        prev_deps = curr_deps
        prev_outdated = curr_outdated
        if curr_outdated is not None:
            latest_outdated = curr_outdated

    if len(analysed) < 2:
        first_date_str = analysed[0]["created_at"].isoformat() if analysed else ""
        return _empty_metrics(project_id, project_name, len(analysed), first_date_str, branch=analyzed_branch)

    upstream = await _maybe_fetch_upstream_cadence(release_fetcher, state.package_specs, state.first_seen_versions)

    # Past the cap the walk never saw the older part of the window, so the rate divides by
    # the stretch it did fold rather than by a window it only partly covered.
    rate_days = _spanned_days(analysed) if truncated else window_days

    return _aggregate_metrics(
        analysed,
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
        latest_outdated=latest_outdated,
        final_versions=_final_versions_by_name(prev_deps),
        window_days=rate_days,
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


def _rate(summary: ProjectUpdateSummary) -> float:
    """Sort key: an unavailable monthly rate ranks below every measured one."""
    return summary.updates_per_month if summary.updates_per_month is not None else -1.0


def rank_summaries(summaries: list[ProjectUpdateSummary]) -> UpdateFrequencyComparison:
    """Order the fully measured projects and list the rest behind them, unranked.

    Coverage of None means no backlog was ever measured, so those rank after
    every measured project and never become best or worst. A ``partial`` row
    carries numbers for a shorter stretch of the window than a ready one, so it
    is listed with its caveat but stays out of the averages and the ranking.
    Rows without any metrics are listed last and named: a bare count of projects
    that could not be measured leaves the reader unable to go and look at them.
    """
    ready = [s for s in summaries if s.data_status == "ready"]
    partial = sorted((s for s in summaries if s.data_status == "partial"), key=lambda s: (-_rate(s), s.project_name))
    pending = sorted((s for s in summaries if s.data_status == "pending"), key=lambda s: s.project_name)
    thin = sorted((s for s in summaries if s.data_status == "insufficient_data"), key=lambda s: s.project_name)
    failed = sorted((s for s in summaries if s.data_status == "error"), key=lambda s: s.project_name)

    measured = [s for s in ready if s.update_coverage_pct is not None]
    unmeasured = [s for s in ready if s.update_coverage_pct is None]
    measured.sort(key=lambda s: (s.update_coverage_pct, _rate(s)), reverse=True)
    unmeasured.sort(key=_rate, reverse=True)

    rates = [s.updates_per_month for s in ready if s.updates_per_month is not None]
    return UpdateFrequencyComparison(
        projects=measured + unmeasured + partial + pending + thin + failed,
        partial_projects=len(partial),
        team_avg_updates_per_month=round(sum(rates) / len(rates), 2) if rates else None,
        team_avg_coverage_pct=(
            round(sum(s.update_coverage_pct for s in measured) / len(measured), 1)  # type: ignore[misc]
            if measured
            else None
        ),
        best_project=measured[0].project_name if measured else None,
        worst_project=measured[-1].project_name if len(measured) >= 2 else None,
        pending_projects=len(pending),
        skipped_insufficient_data=len(thin),
        skipped_error=len(failed),
    )


async def compute_update_frequency_comparison(
    projects: list[dict[str, Any]],
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    window_days: int = 90,
    release_fetcher: ReleaseHistoryFetcher | None = None,
) -> UpdateFrequencyComparison:
    """Cross-project update-frequency ranking.

    Per-project computations run with bounded concurrency. ``window_days``
    aligns every project on the same calendar window; ranking projects across
    different spans would compare scan cadence rather than update activity.
    One batched read of the scan window feeds both the branch choice and the
    coverage verdict, so a project scanned outside the window costs no query.
    """
    # Created per call so it binds to the loop running this gather (see note
    # at module top); a module-global semaphore would pin to the first loop.
    semaphore = asyncio.Semaphore(_COMPARISON_CONCURRENCY)
    since = window_cutoff(window_days)

    def _project_key(project: dict[str, Any]) -> str:
        return str(project.get("_id") or project.get("id", ""))

    activity = await window_scans_by_branch(scan_repo, [_project_key(p) for p in projects], since)
    by_project: dict[str, dict[str, BranchWindowActivity]] = {}
    for (project_id, branch), seen in activity.items():
        by_project.setdefault(project_id, {})[branch] = seen

    def _placeholder(
        project: dict[str, Any], status: UpdateDataStatus, branch: str | None = None
    ) -> ProjectUpdateSummary:
        """A row without numbers, naming the branch it looked at, so every project stays accounted for once."""
        return ProjectUpdateSummary(
            project_id=_project_key(project),
            project_name=project.get("name", ""),
            team_name=project.get("team_name"),
            data_status=status,
            branch=branch,
            window_days=window_days,
        )

    async def _compute_single(project: dict[str, Any]) -> ProjectUpdateSummary:
        project_id = _project_key(project)
        project_name = project.get("name", "")
        team_name = project.get("team_name")

        branches = by_project.get(project_id, {})
        primary = select_primary_branch(branches, project.get("default_branch"), project.get("deleted_branches"))
        if primary is None:
            return _placeholder(project, "insufficient_data")

        async with semaphore:
            try:
                metrics = await compute_update_frequency(
                    project_id=project_id,
                    project_name=project_name,
                    scan_repo=scan_repo,
                    dep_repo=dep_repo,
                    analysis_repo=analysis_repo,
                    window_days=window_days,
                    release_fetcher=release_fetcher,
                    branch=primary,
                )
            except Exception:
                logger.warning(f"Failed to compute update frequency for project {project_id}", exc_info=True)
                return _placeholder(project, "error", primary)

            if metrics.scan_count < 2:
                return _placeholder(project, "insufficient_data", primary)

            return ProjectUpdateSummary(
                project_id=metrics.project_id,
                project_name=metrics.project_name,
                team_name=team_name,
                # The walk reads the very scans coverage is measured against, so it
                # cannot fall behind them the way the delta ledger can.
                data_status="ready",
                branch=metrics.branch,
                window_days=window_days,
                scan_count=metrics.scan_count,
                updates_per_month=metrics.updates_per_month,
                update_coverage_pct=metrics.update_coverage_pct,
                patch_ratio=metrics.granularity_ratio.get("patch", 0),
                trend_direction=metrics.trend_direction,
                total_updates=metrics.total_updates,
                total_outdated=metrics.total_outdated_detected,
                last_scan_date=metrics.last_scan_date,
            )

    results = await asyncio.gather(*[_compute_single(p) for p in projects], return_exceptions=True)
    summaries = [
        r
        if isinstance(r, ProjectUpdateSummary)
        # gather() hands back anything that escaped _compute_single's own guard.
        else _placeholder(project, "error")
        for project, r in zip(projects, results, strict=True)
    ]
    for outcome in results:
        if isinstance(outcome, BaseException):
            logger.warning("Update-frequency comparison lost a project", exc_info=outcome)

    return rank_summaries(summaries)
