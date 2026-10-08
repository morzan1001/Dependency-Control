"""Update-frequency analytics: compare dependency versions across scans.

Streaming model — one scan pair at a time so peak memory stays at
~2 x deps/scan regardless of project size.
"""

import asyncio
import logging
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import chain, islice
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

from app.core.constants import (
    COUNTED_UPDATE_KINDS,
    RECENT_UPDATES_LIMIT,
    SLOWEST_PACKAGES_LIMIT,
    UPDATE_SAMPLE_RANK,
    UpdateKind,
)
from app.core.purl import package_identity, parse_purl
from app.repositories.analysis_results import RESULT_PROJECTION, AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    WINDOW_HARD_LIMIT,
    BranchWindowActivity,
    usable_scan_match,
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
from app.schemas.team import TeamRef
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

DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "purl": 1, "group": 1}

DAYS_PER_MONTH = 30.44


def _release_tuple(version: Version) -> tuple[int, int]:
    """``(major, minor)`` padded with zeros for shorter release tuples."""
    release = version.release
    return (
        release[0] if len(release) > 0 else 0,
        release[1] if len(release) > 1 else 0,
    )


def classify_version_change(old_version: str, new_version: str) -> UpdateKind | Literal["none"]:
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
    """``(package_identity, info)`` of a dependency; info keeps the bare ``name`` analyzer results are keyed by."""
    name = dep.get("name", "")
    if not name:
        return None
    purl = dep.get("purl", "")
    identity = ":".join(package_identity(purl, name, dep.get("type"), dep.get("group")))
    parsed = parse_purl(purl) if purl else None
    if parsed:
        deps_dev_name = parsed.deps_dev_name
        display = parsed.full_name
        # SBOM component types ("library") say nothing about the ecosystem; the purl type does.
        dep_type = parsed.type
        deps_dev_system = parsed.deps_dev_system or ""
    else:
        deps_dev_name = ""
        display = name
        dep_type = dep.get("type", "unknown")
        deps_dev_system = ""
    return identity, {
        "version": dep.get("version", ""),
        "type": dep_type,
        "purl": purl,
        "name": name,
        "display": display,
        "deps_dev_system": deps_dev_system,
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


async def load_scan_deps(dep_repo: DependencyRepository, scan_id: str) -> dict[str, dict[str, str]]:
    return fold_scan_deps(await dep_repo.find_all_raw({"scan_id": scan_id}, DEP_PROJECTION))


async def load_outdated_entries(analysis_repo: AnalysisResultRepository, scan_id: str) -> list[dict[str, Any]] | None:
    """The scan's ``outdated_dependencies`` entries, or None when it carries no such analysis.

    An analyzer that raised leaves no document behind and one that failed stores a
    result without ``outdated_dependencies``; reading either as an empty backlog
    would report the whole backlog of the previous scan as brought up to date. A
    result whose lookups partly failed leaves those packages unflagged, so one
    such row leaves the whole scan unmeasured.

    One row is stored per SBOM of the scan and the caller folds them into a set, so the
    cursor is walked whole: a bounded read would drop an arbitrary SBOM's backlog.
    """
    entries: list[dict[str, Any]] = []
    measured = False
    async for doc in analysis_repo.iterate_raw(
        {"scan_id": scan_id, "analyzer_name": "outdated_packages"}, projection=RESULT_PROJECTION
    ):
        result = await analysis_repo.load_result(doc) or {}
        found = result.get("outdated_dependencies")
        if not isinstance(found, list):
            continue
        if result.get("partial_components_skipped"):
            return None
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


def _update_sample_order(event: DependencyUpdateEvent) -> tuple[int, str, str]:
    """The order the delta writer sorts its samples in, so both paths cut a scan the same way."""
    return (UPDATE_SAMPLE_RANK[event.update_type], event.package_name, event.new_version)


def version_changes(
    prev_deps: dict[str, dict[str, str]], curr_deps: dict[str, dict[str, str]]
) -> Iterator[tuple[str, dict[str, str], dict[str, str], UpdateKind]]:
    """``(identity, previous, current, kind)`` of every dependency whose version moved between two scans."""
    for identity, curr in curr_deps.items():
        prev = prev_deps.get(identity)
        if prev is None or prev["version"] == curr["version"]:
            continue
        kind = classify_version_change(prev["version"], curr["version"])
        if kind != "none":  # "none" is one PEP 440 identity spelled twice, e.g. v1.0.0 vs 1.0.0
            yield identity, prev, curr, kind


def _compare_scan_pair(
    prev_deps: dict[str, dict[str, str]],
    prev_scan_date: datetime,
    curr_deps: dict[str, dict[str, str]],
    curr_scan_date: datetime,
    prev_outdated: set[str] | None,
) -> list[tuple[DependencyUpdateEvent, str]]:
    """Compare two consecutive scans, returning ``(event, identity)`` pairs."""
    days_between = max(1, (curr_scan_date - prev_scan_date).days)
    return [
        (
            DependencyUpdateEvent(
                package_name=curr["display"],
                package_type=curr["type"],
                purl=curr["purl"] or None,
                old_version=prev["version"],
                new_version=curr["version"],
                update_type=kind,
                scan_date=curr_scan_date.isoformat(),
                previous_scan_date=prev_scan_date.isoformat(),
                days_between_scans=days_between,
                was_outdated=prev["name"] in (prev_outdated or ()),
            ),
            identity,
        )
        for identity, prev, curr, kind in version_changes(prev_deps, curr_deps)
    ]


def _build_timeline_entry(
    scan_id: str,
    scan_date: datetime,
    events: list[DependencyUpdateEvent],
    outdated_count: int | None,
) -> ScanTimelineEntry:
    """Build a timeline entry from a list of update events for a scan."""
    type_counts = Counter(e.update_type for e in events)
    return ScanTimelineEntry(
        scan_id=scan_id,
        date=scan_date.isoformat(),
        updates_count=sum(type_counts[kind] for kind in COUNTED_UPDATE_KINDS),
        outdated_count=outdated_count,
        patch=type_counts.get("patch", 0),
        minor=type_counts.get("minor", 0),
        major=type_counts.get("major", 0),
        unknown=type_counts.get("unknown", 0),
        downgrades=type_counts.get("downgrade", 0),
    )


def _mean_outdated(entries: Sequence[ScanTimelineEntry]) -> float | None:
    """Mean backlog over the scans that carried an outdated analysis, or None if none did."""
    measured = [s.outdated_count for s in entries if s.outdated_count is not None]
    if not measured:
        return None
    return sum(measured) / len(measured)


def compute_trend(scan_timeline: Sequence[ScanTimelineEntry]) -> tuple[str, str]:
    """Trend ``(direction, detail)`` from comparing the first vs second half of the timeline.

    The leading entry is excluded because its incoming edge lies outside the
    window: its height is not comparable with the others, and averaging it in
    would report "improving" for every project with a steady update rate. The
    backlog signal is dropped when either half has no outdated analysis, since
    a missing measurement is not a backlog of zero.
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


def granularity_ratio(kinds: Mapping[str, int], total_updates: int) -> dict[str, float]:
    """Per-update-type share of all updates, rounded to 2 dp."""
    return {
        bucket: round(kinds.get(bucket, 0) / total_updates, 2) if total_updates else 0.0
        for bucket in COUNTED_UPDATE_KINDS
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

    def to_metrics(
        self,
        project_id: str,
        project_name: str,
        *,
        branch: str | None = None,
        slowest_packages: Sequence[SlowPackage] = (),
        recent_updates: Sequence[DependencyUpdateEvent] = (),
        upstream: UpstreamCadenceMetrics | None = None,
        window_scan_cap: int | None = None,
        outdated_backlog: int = 0,
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
            window_scan_cap=window_scan_cap,
            outdated_backlog=outdated_backlog,
            scan_timeline=self.scan_timeline,
            slowest_packages=list(slowest_packages),
            recent_updates=list(recent_updates),
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
        teams: list[TeamRef] | None = None,
        *,
        branch: str | None = None,
        window_days: int,
        data_status: Literal["ready", "partial"] = "ready",
        window_scan_cap: int | None = None,
    ) -> ProjectUpdateSummary:
        """A row carrying the folded numbers.

        ``data_status`` is the caller's verdict from ``window_coverage_status``:
        the fold knows what it summed, not how many scans the window really held.
        """
        return ProjectUpdateSummary(
            project_id=project_id,
            project_name=project_name,
            teams=teams or [],
            data_status=data_status,
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
            window_scan_cap=window_scan_cap,
        )


def summarise_window(
    bars: list[ScanTimelineEntry],
    kinds: Mapping[str, int],
    ever_outdated: set[str],
    ever_resolved: set[str],
    rate_days: int | None,
    ecosystem: str | None,
) -> FoldedWindow:
    """The metrics of a window of at least two bars, from the movement summed over its scan pairs.

    Both read paths end here, so the walk and the ledger fold derive every number alike.
    ``rate_days`` is the stretch the monthly rate divides by, or None without a calendar window.
    """
    total_updates = sum(kinds.get(kind, 0) for kind in COUNTED_UPDATE_KINDS)
    num_intervals = len(bars) - 1

    first_date = datetime.fromisoformat(bars[0].date)
    last_date = datetime.fromisoformat(bars[-1].date)
    raw_range_days = (last_date - first_date).total_seconds() / 86400.0

    resolved_count = len(ever_outdated & ever_resolved)
    trend_direction, trend_detail = compute_trend(bars)

    return FoldedWindow(
        scan_count=len(bars),
        # Floored at one day so the rendered span never reads as zero.
        time_range_days=round(max(1.0, raw_range_days), 2),
        first_scan_date=first_date.isoformat(),
        last_scan_date=last_date.isoformat(),
        total_updates=total_updates,
        updates_per_scan=round(total_updates / num_intervals, 2),
        updates_per_month=updates_per_month(total_updates, rate_days),
        patch_updates=kinds.get("patch", 0),
        minor_updates=kinds.get("minor", 0),
        major_updates=kinds.get("major", 0),
        unknown_updates=kinds.get("unknown", 0),
        downgrade_updates=kinds.get("downgrade", 0),
        granularity_ratio=granularity_ratio(kinds, total_updates),
        # Cadence reports the real average interval, not the floored range.
        avg_days_between_scans=round(raw_range_days / num_intervals, 1),
        total_outdated_detected=len(ever_outdated),
        outdated_resolved=resolved_count,
        # Both sets carry measured scans only, so None means "no backlog was ever
        # measured here" -- distinct from 0.0 ("measured, nothing resolved").
        update_coverage_pct=(round(resolved_count / len(ever_outdated) * 100, 1) if ever_outdated else None),
        trend_direction=trend_direction,
        trend_detail=trend_detail,
        dominant_ecosystem=ecosystem,
        scan_timeline=bars,
    )


def short_window(bars: Sequence[ScanTimelineEntry]) -> FoldedWindow:
    """A window with fewer than two bars supports no comparison at all."""
    scan_date = bars[0].date if bars else ""
    return FoldedWindow(
        scan_count=len(bars),
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
) -> tuple[list[SlowPackage], int]:
    """The rows of the slowest-to-update table and the backlog they are the head of.

    Only packages still outdated in the newest scan that carried an outdated
    analysis qualify — resolved ones are history, not backlog, and a scan
    without the analysis is not a cleared backlog. ``current_version`` comes
    from the newest scan's dependency set; analyzer entries may be scans old.
    """
    remaining = {pkg: count for pkg, count in package_outdated_counts.items() if pkg in latest_outdated}
    slowest = sorted(remaining.items(), key=lambda entry: (-entry[1], entry[0]))[:SLOWEST_PACKAGES_LIMIT]
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
    ], len(remaining)


# Bounds the (package, version) -> first_scan_date map used for adoption-latency.
# Far above realistic projects; protects against pathological version churn.
_MAX_OBSERVATIONS = 10_000

ECOSYSTEM_DOMINANCE_THRESHOLD = 0.7


def ecosystem_counts(deps: dict[str, dict[str, str]]) -> dict[str, int]:
    return dict(Counter(info["type"] for info in deps.values()))


def dominant_ecosystem(eco: Mapping[str, Any]) -> str | None:
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


@dataclass
class _AccumulatorState:
    """Streaming-loop state, bundled so each helper takes a single argument."""

    type_counter: Counter = field(default_factory=Counter)
    # One rank-ordered list per scan that produced changes, so the newest-first read below
    # keeps the same events out of a busy scan as the delta writer's samples do.
    recent_events_by_scan: deque[list[DependencyUpdateEvent]] = field(
        default_factory=lambda: deque(maxlen=RECENT_UPDATES_LIMIT)
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
            system = info["deps_dev_system"]
            if system and identity not in self.package_specs:
                self.package_specs[identity] = (system, info["deps_dev_name"])

    def record_outdated(self, outdated: set[str] | None) -> None:
        """A backlog observed anywhere in the window counts, whether or not it names a bar."""
        self.ever_outdated.update(outdated or ())

    def record_bar_outdated(self, outdated: set[str] | None) -> None:
        """The per-package tally counts bars, so only a run's representative feeds it."""
        for pkg in outdated or ():
            self.package_outdated_counts[pkg] += 1

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
            # Returning to an old release is no adoption of it.
            if e.update_type != "downgrade" and len(self.first_seen_versions) < _MAX_OBSERVATIONS:
                key = (identity, e.new_version)
                if key not in self.first_seen_versions:
                    self.first_seen_versions[key] = curr_scan_date
        if events:
            ranked = sorted((e for e, _identity in events), key=_update_sample_order)
            self.recent_events_by_scan.append(ranked[:RECENT_UPDATES_LIMIT])

    def recent_events(self) -> list[DependencyUpdateEvent]:
        """Newest scan first, rank-ordered within a scan, cut at the shared limit."""
        return list(islice(chain.from_iterable(reversed(self.recent_events_by_scan)), RECENT_UPDATES_LIMIT))


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


async def elect_primary_branch(
    scan_repo: ScanRepository,
    project_id: str,
    since: datetime | None,
    default_branch: str | None,
    deleted_branches: Sequence[str] | None,
) -> str | None:
    """One project's primary branch in the window."""
    activity = await window_scans_by_branch(scan_repo, [project_id], since)
    return select_primary_branch(activity.get(project_id, {}), default_branch, deleted_branches)


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


def same_commit_runs[T](items: Sequence[T], *, commit_of: Callable[[T], str | None]) -> list[list[T]]:
    """Group one branch's window scans into same-commit runs, oldest first.

    Both read paths sum movement over every consecutive pair of window scans. A
    run only merges those scans into one timeline bar, named by the run's last
    scan; it never removes a pair from a sum. The bars therefore tile the pairs:
    ``sum(bar.updates_count) == total_updates``, so a rate over the bars still
    accounts for the pairs that fall inside a run.

    A scan naming no commit stands for itself.
    """
    runs: list[list[T]] = []
    for item in items:
        commit = commit_of(item)
        if runs and commit and commit_of(runs[-1][-1]) == commit:
            runs[-1].append(item)
        else:
            runs.append([item])
    return runs


def fold_runs_into_bars(entries: Sequence[ScanTimelineEntry], commits: Sequence[str | None]) -> list[ScanTimelineEntry]:
    """One bar per same-commit run, named and dated by the run's last scan."""
    pairs = list(zip(entries, commits, strict=True))
    bars: list[ScanTimelineEntry] = []
    for run in same_commit_runs(pairs, commit_of=lambda pair: pair[1]):
        members = [entry for entry, _commit in run]
        last = members[-1]
        bars.append(
            ScanTimelineEntry(
                scan_id=last.scan_id,
                date=last.date,
                updates_count=sum(m.updates_count for m in members),
                outdated_count=last.outdated_count,
                patch=sum(m.patch for m in members),
                minor=sum(m.minor for m in members),
                major=sum(m.major for m in members),
                unknown=sum(m.unknown for m in members),
                downgrades=sum(m.downgrades for m in members),
            )
        )
    return bars


# max_scans counts timeline bars, and a bar can hold a whole run; over-fetch so a
# burst of CI retries on the head commit can't starve the window below max_scans.
_BAR_FETCH_HEADROOM = 5


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
    fetch_limit = hard_limit if since is not None else min(hard_limit, max_scans * _BAR_FETCH_HEADROOM)
    # Filter status and window in the query so the limit counts only scans the walk can use;
    # filtering after the limit would empty the window when the newest scans are failed/processing.
    docs = await scan_repo.find_many_raw(
        {**usable_scan_match(since), "project_id": project_id, "branch": branch},
        sort=[("created_at", -1), ("_id", -1)],
        limit=fetch_limit,
        projection={"_id": 1, "created_at": 1, "commit_hash": 1},
    )
    scans_raw: list[dict[str, Any]] = [
        {"_id": d["_id"], "created_at": d["created_at"], "commit_hash": d.get("commit_hash")}
        for d in docs
        # Archive restore inserts bundle JSON verbatim, so a date can arrive as an ISO string.
        # Neither the window aggregation nor the delta writer matches those, so analysing them
        # here would put scans on the timeline that nothing else in the pipeline accounts for.
        if isinstance(d.get("created_at"), datetime)
    ]
    scans_raw.reverse()
    if since is None:
        # Cap whole runs, so a retry storm cannot thin the window below max_scans bars.
        runs = same_commit_runs(scans_raw, commit_of=lambda scan: scan["commit_hash"])
        return [scan for run in runs[-max_scans:] for scan in run], False
    # A full fetch means older scans of the window went unread, so the window the caller
    # asked for is wider than the stretch it is about to fold.
    return scans_raw, len(docs) >= fetch_limit


def spanned_days(first: datetime, last: datetime) -> int:
    """Whole days a folded stretch covers, floored at one so a burst cannot inflate a rate."""
    return max(1, round((last - first).total_seconds() / 86400))


async def compute_update_frequency(
    project_id: str,
    project_name: str,
    scan_repo: ScanRepository,
    dep_repo: DependencyRepository,
    analysis_repo: AnalysisResultRepository,
    branch: str | None,
    max_scans: int = 20,
    window_days: int | None = None,
    release_fetcher: ReleaseHistoryFetcher | None = None,
    hard_limit: int = WINDOW_HARD_LIMIT,
) -> UpdateFrequencyMetrics:
    """One branch's metrics (other branches' differences are no updates); only ``window_days`` yields a monthly rate."""
    if branch is None:
        return short_window([]).to_metrics(project_id, project_name)
    since = window_cutoff(window_days)

    completed_scans, truncated = await _load_completed_scans(
        scan_repo, project_id, branch, max_scans, since, hard_limit
    )

    state = _AccumulatorState()

    analysed: list[dict[str, Any]] = []
    prev_deps: dict[str, dict[str, str]] = {}
    prev_outdated: set[str] | None = None
    latest_outdated: set[str] | None = None

    def _close_bar() -> None:
        """The previous survivor ended its run, so it is the scan the bar tallies read."""
        nonlocal latest_outdated
        state.record_bar_outdated(prev_outdated)
        if prev_outdated is not None:
            latest_outdated = prev_outdated

    for curr_scan in completed_scans:
        curr_deps = await load_scan_deps(dep_repo, curr_scan["_id"])
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
            if not curr_scan["commit_hash"] or prev_scan["commit_hash"] != curr_scan["commit_hash"]:
                _close_bar()
            state.record_resolved(prev_outdated, curr_outdated, curr_deps)
            events = _compare_scan_pair(
                prev_deps, prev_scan["created_at"], curr_deps, curr_scan["created_at"], prev_outdated
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

    if analysed:
        _close_bar()
    bars = fold_runs_into_bars(state.scan_timeline, [scan["commit_hash"] for scan in analysed])

    if len(bars) < 2:
        return short_window(bars).to_metrics(project_id, project_name, branch=branch)

    upstream = await _maybe_fetch_upstream_cadence(release_fetcher, state.package_specs, state.first_seen_versions)
    slowest_packages, outdated_backlog = _build_slowest_packages(
        state.package_outdated_counts,
        state.package_latest_info,
        state.dep_type_map,
        latest_outdated or set(),
        _final_versions_by_name(prev_deps),
    )
    # Past the cap the walk never saw the older part of the window, so the rate divides by
    # the stretch it did fold rather than by a window it only partly covered.
    rate_days = (
        spanned_days(datetime.fromisoformat(bars[0].date), datetime.fromisoformat(bars[-1].date))
        if truncated
        else window_days
    )
    folded = summarise_window(
        bars,
        state.type_counter,
        state.ever_outdated,
        state.ever_resolved,
        rate_days,
        dominant_ecosystem(ecosystem_counts(prev_deps)),
    )
    return folded.to_metrics(
        project_id,
        project_name,
        branch=branch,
        slowest_packages=slowest_packages,
        recent_updates=state.recent_events(),
        upstream=upstream,
        window_scan_cap=hard_limit if truncated else None,
        outdated_backlog=outdated_backlog,
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


def _project_key(project: dict[str, Any]) -> str:
    return str(project.get("_id") or project.get("id", ""))


def placeholder_summary(
    project: dict[str, Any], status: UpdateDataStatus, window_days: int, branch: str | None = None
) -> ProjectUpdateSummary:
    """A row without numbers, naming the branch it looked at, so every project stays accounted for once."""
    return ProjectUpdateSummary(
        project_id=_project_key(project),
        project_name=project.get("name", ""),
        teams=project.get("teams") or [],
        data_status=status,
        branch=branch,
        window_days=window_days,
    )


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

    activity = await window_scans_by_branch(scan_repo, [_project_key(p) for p in projects], since)

    async def _compute_single(project: dict[str, Any]) -> ProjectUpdateSummary:
        project_id = _project_key(project)
        project_name = project.get("name", "")
        teams = project.get("teams") or []

        branches = activity.get(project_id, {})
        primary = select_primary_branch(branches, project.get("default_branch"), project.get("deleted_branches"))
        if primary is None:
            return placeholder_summary(project, "insufficient_data", window_days)

        async with semaphore:
            try:
                metrics = await compute_update_frequency(
                    project_id=project_id,
                    project_name=project_name,
                    scan_repo=scan_repo,
                    dep_repo=dep_repo,
                    analysis_repo=analysis_repo,
                    window_days=window_days,
                    branch=primary,
                )
            except Exception:
                logger.warning(f"Failed to compute update frequency for project {project_id}", exc_info=True)
                return placeholder_summary(project, "error", window_days, primary)

            if metrics.scan_count < 2:
                return placeholder_summary(project, "insufficient_data", window_days, primary)

            return ProjectUpdateSummary(
                project_id=metrics.project_id,
                project_name=metrics.project_name,
                teams=teams,
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
                window_scan_cap=metrics.window_scan_cap,
            )

    results = await asyncio.gather(*[_compute_single(p) for p in projects], return_exceptions=True)
    summaries = [
        r
        if isinstance(r, ProjectUpdateSummary)
        # gather() hands back anything that escaped _compute_single's own guard.
        else placeholder_summary(project, "error", window_days)
        for project, r in zip(projects, results, strict=True)
    ]
    for outcome in results:
        if isinstance(outcome, BaseException):
            logger.warning("Update-frequency comparison lost a project", exc_info=outcome)

    return rank_summaries(summaries)
