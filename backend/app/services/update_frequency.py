"""One scan pair at a time, so peak memory stays at ~2 x deps/scan regardless of project size."""

import asyncio
import heapq
import logging
import re
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import chain, islice
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

from app.api.v1.helpers.sorting import case_insensitive_key
from app.core.constants import (
    COUNTED_UPDATE_KINDS,
    RECENT_UPDATES_LIMIT,
    RETENTION_ACTION_ARCHIVE,
    RETENTION_ACTION_DELETE,
    SETTINGS_MODE_GLOBAL,
    SLOWEST_PACKAGES_LIMIT,
    UPDATE_FREQUENCY_COMPARISON_WINDOW_DAYS,
    UPDATE_SAMPLE_RANK,
    UpdateKind,
)
from app.core.purl import parse_purl, parsed_package_identity
from app.core.s3 import is_archive_enabled
from app.models.system import SystemSettings
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
from app.services.aggregation.versions import parse_version_key
from app.services.release_history import (
    Observation,
    ReleaseHistoryFetcher,
    UpstreamCadenceMetrics,
    aggregate_upstream_metrics,
)

logger = logging.getLogger(__name__)

_COMPARISON_CONCURRENCY = 3

DEP_PROJECTION = {"name": 1, "version": 1, "type": 1, "purl": 1, "group": 1}

DAYS_PER_MONTH = 30.44


def _release_tuple(version: Version) -> tuple[int, int]:
    release = version.release
    return (
        release[0] if len(release) > 0 else 0,
        release[1] if len(release) > 1 else 0,
    )


# Hex digests order at random, so ranking two commit pins would book half of all pin bumps as downgrades.
_COMMIT_HASH = re.compile(r"[0-9a-f]{7,64}")
# A Debian epoch outranks the whole version after it, which parse_version_key would read as one more number.
_DEBIAN_EPOCH = re.compile(r"(\d+):")


def _debian_epoch(version: str) -> int:
    match = _DEBIAN_EPOCH.match(version)
    return int(match.group(1)) if match else 0


def _classify_outside_pep_440(old_version: str, new_version: str) -> UpdateKind | Literal["none"]:
    """Maven, Debian and Go spellings: ordered for direction only, as their parts name no major, minor or patch."""
    if _COMMIT_HASH.fullmatch(old_version) or _COMMIT_HASH.fullmatch(new_version):
        return "unknown"
    old_epoch, new_epoch = _debian_epoch(old_version), _debian_epoch(new_version)
    if old_epoch != new_epoch:
        return "downgrade" if new_epoch < old_epoch else "unknown"
    old_key, new_key = parse_version_key(old_version), parse_version_key(new_version)
    if new_key < old_key:
        return "downgrade"
    return "none" if new_key == old_key else "unknown"


def classify_version_change(old_version: str, new_version: str) -> UpdateKind | Literal["none"]:
    """Backwards moves are downgrades, so rollbacks never count as activity; pre/post/local changes count as patch."""
    try:
        old_v = Version(old_version)
        new_v = Version(new_version)
    except InvalidVersion:
        return _classify_outside_pep_440(old_version, new_version)

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
    """info keeps the bare name that analyzer results are keyed by."""
    name = dep.get("name", "")
    if not name:
        return None
    purl = dep.get("purl", "")
    parsed = parse_purl(purl) if purl else None
    identity = ":".join(parsed_package_identity(parsed, name, dep.get("type"), dep.get("group")))
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
    """The tie-break must not depend on Mongo document order, which is unstable and would fabricate version changes."""
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
    return max(candidates, key=lambda cand: (parse_version_key(cand["version"]), cand["version"]))


def fold_scan_deps(deps: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    candidates: dict[str, list[dict[str, str]]] = defaultdict(list)
    for dep in deps:
        record = _dep_record(dep)
        if record:
            identity, info = record
            candidates[identity].append(info)
    return {identity: _resolve_duplicate(infos) for identity, infos in candidates.items()}


async def load_scan_deps(dep_repo: DependencyRepository, scan_id: str) -> dict[str, dict[str, str]]:
    return fold_scan_deps(await dep_repo.find_all_raw({"scan_id": scan_id}, DEP_PROJECTION))


async def load_outdated_entries(
    analysis_repo: AnalysisResultRepository, scan_id: str
) -> tuple[list[dict[str, Any]], set[str]] | None:
    """None without an analysis, which must not read as an empty backlog; each SBOM stores a row, so read all."""
    entries: list[dict[str, Any]] = []
    failed: set[str] = set()
    measured = False
    async for doc in analysis_repo.iterate_raw(
        {"scan_id": scan_id, "analyzer_name": "outdated_packages"}, projection=RESULT_PROJECTION
    ):
        result = await analysis_repo.load_result(doc) or {}
        found = result.get("outdated_dependencies")
        if not isinstance(found, list):
            continue
        measured = True
        entries.extend(found)
        failed.update(result.get("lookup_failed_components") or ())
    return (entries, failed) if measured else None


async def _load_outdated_for_scan(
    analysis_repo: AnalysisResultRepository,
    scan_id: str,
    package_latest_info: dict[str, dict[str, str]],
) -> tuple[set[str] | None, set[str]]:
    """Updates package_latest_info in place; last write wins, as slowest_packages needs one pair per name."""
    loaded = await load_outdated_entries(analysis_repo, scan_id)
    if loaded is None:
        return None, set()
    entries, failed = loaded
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
    return outdated_names, failed


def _measured_count(outdated: set[str] | None) -> int | None:
    return None if outdated is None else len(outdated)


_VersionChange = tuple[str, dict[str, str], dict[str, str], UpdateKind]


def version_changes(
    prev_deps: dict[str, dict[str, str]], curr_deps: dict[str, dict[str, str]]
) -> Iterator[_VersionChange]:
    for identity, curr in curr_deps.items():
        prev = prev_deps.get(identity)
        if prev is None or prev["version"] == curr["version"]:
            continue
        kind = classify_version_change(prev["version"], curr["version"])
        # "none": one version spelled twice, e.g. v1.0.0 vs 1.0.0 or 4.1.100.Final vs 4.1.100
        if kind != "none":
            yield identity, prev, curr, kind


def resolved_outdated(
    prev_outdated: set[str], curr_outdated: set[str], curr_deps: dict[str, dict[str, str]], curr_failed: set[str]
) -> set[str]:
    """A package that vanished, or whose lookup failed, was not brought up to date."""
    return (prev_outdated & ({info["name"] for info in curr_deps.values()} - curr_failed)) - curr_outdated


def _update_sample_order(change: _VersionChange) -> tuple[int, str, str]:
    """Mongo document order is unstable, so the cut of a busy scan needs a total order of its own."""
    _identity, _prev, curr, kind = change
    return (UPDATE_SAMPLE_RANK[kind], curr["display"], curr["version"])


def _sample_events(
    changes: list[_VersionChange],
    prev_scan_date: datetime,
    curr_scan_date: datetime,
    prev_outdated: set[str] | None,
) -> list[DependencyUpdateEvent]:
    days_between = max(1, (curr_scan_date - prev_scan_date).days)
    return [
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
        )
        for _identity, prev, curr, kind in heapq.nsmallest(RECENT_UPDATES_LIMIT, changes, key=_update_sample_order)
    ]


def _build_timeline_entry(
    scan_id: str,
    scan_date: datetime,
    type_counts: Mapping[str, int],
    outdated_count: int | None,
) -> ScanTimelineEntry:
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
    measured = [s.outdated_count for s in entries if s.outdated_count is not None]
    if not measured:
        return None
    return sum(measured) / len(measured)


def compute_trend(scan_timeline: Sequence[ScanTimelineEntry]) -> tuple[str, str]:
    """The leading entry's incoming edge lies outside the window, so it is excluded; a missing backlog is not zero."""
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
    return {
        bucket: round(kinds.get(bucket, 0) / total_updates, 2) if total_updates else 0.0
        for bucket in COUNTED_UPDATE_KINDS
    }


def window_cutoff(window_days: int | None) -> datetime | None:
    if window_days is None:
        return None
    return datetime.now(tz=timezone.utc) - timedelta(days=window_days)


def retention_horizon(system: SystemSettings, project_days: int | None, project_action: str | None) -> int | None:
    """Days of scans retention keeps, None where it deletes none; the head and released scans outlive it."""
    if system.retention_mode == SETTINGS_MODE_GLOBAL:
        days, action = system.global_retention_days, system.global_retention_action
    else:
        days, action = project_days or 0, project_action or RETENTION_ACTION_DELETE
    deletes = action == RETENTION_ACTION_DELETE or (action == RETENTION_ACTION_ARCHIVE and is_archive_enabled())
    return days if days > 0 and deletes else None


def retained_window(window_days: int, horizon: int | None) -> int | None:
    """The horizon when it is shorter than the window: no scan older than it is left to count, so the rate stops there."""
    return horizon if horizon is not None and horizon < window_days else None


def updates_per_month(total_updates: int, window_days: int | None) -> float | None:
    """Per calendar window, not scan span, so CI cadence cannot skew the ranking's primary sort key."""
    if window_days is None:
        return None
    return round(total_updates / (window_days / DAYS_PER_MONTH), 2)


# Two bars make the first interval; a commit run is one bar, so it also takes two commits.
MIN_COMPARABLE_BARS = 2

_NOT_ENOUGH_SCANS = f"Not enough scans to analyze (need at least {MIN_COMPARABLE_BARS})"


@dataclass(frozen=True)
class FoldedWindow:
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
        retention_days: int | None = None,
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
            retention_days=retention_days,
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


def summarise_window(
    bars: list[ScanTimelineEntry],
    kinds: Mapping[str, int],
    ever_outdated: set[str],
    ever_resolved: set[str],
    rate_days: int | None,
    ecosystem: str | None,
) -> FoldedWindow:
    """Needs two or more bars; rate_days is None without a calendar window."""
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
        # None means no backlog was ever measured, unlike 0.0 (measured, nothing resolved).
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
    """Ambiguous bare names (npm scopes are dropped in storage) are omitted so a sibling's version never shows."""
    counts: Counter = Counter(info["name"] for info in final_deps.values())
    return {info["name"]: info["version"] for info in final_deps.values() if counts[info["name"]] == 1}


def _build_slowest_packages(
    package_outdated_counts: dict[str, int],
    package_latest_info: dict[str, dict[str, str]],
    dep_type_map: dict[str, str],
    latest_outdated: set[str],
    final_versions: dict[str, str],
) -> tuple[list[SlowPackage], int]:
    """A scan without the analysis is no cleared backlog; analyzer entries may be stale, so current_version is fresh."""
    remaining = {pkg: count for pkg, count in package_outdated_counts.items() if pkg in latest_outdated}
    slowest = sorted(remaining.items(), key=lambda entry: (-entry[1], case_insensitive_key(entry[0])))[
        :SLOWEST_PACKAGES_LIMIT
    ]
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


# Far above realistic projects; it guards the adoption-latency map against pathological version churn.
_MAX_OBSERVATIONS = 10_000

ECOSYSTEM_DOMINANCE_THRESHOLD = 0.7


def dominant_ecosystem(eco: Mapping[str, Any]) -> str | None:
    """Only the newest scan counts, so long-removed deps cannot sway what the project holds now."""
    counts = {name: int(n) for name, n in eco.items() if name and name != "unknown" and int(n) > 0}
    if not counts:
        return None
    top_type, top_count = max(counts.items(), key=lambda item: item[1])
    if top_count / sum(counts.values()) >= ECOSYSTEM_DOMINANCE_THRESHOLD:
        return top_type
    return "mixed"


@dataclass
class _AccumulatorState:
    # Adoption feeds only the upstream cadence, which needs a release fetcher.
    track_adoption: bool
    type_counter: Counter = field(default_factory=Counter)
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
            if self.track_adoption and system and identity not in self.package_specs:
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
        curr_failed: set[str],
    ) -> None:
        """Both scans need an outdated analysis: a missing one would report the predecessor's whole backlog resolved."""
        if prev_outdated is None or curr_outdated is None:
            return
        self.ever_resolved |= resolved_outdated(prev_outdated, curr_outdated, curr_deps, curr_failed)

    def absorb_changes(
        self,
        changes: list[_VersionChange],
        prev_scan_date: datetime,
        curr_scan_date: datetime,
        prev_outdated: set[str] | None,
    ) -> Counter[str]:
        kinds: Counter[str] = Counter(kind for *_, kind in changes)
        self.type_counter.update(kinds)
        if self.track_adoption:
            for identity, _prev, curr, kind in changes:
                # Returning to an old release is no adoption of it.
                if kind != "downgrade" and len(self.first_seen_versions) < _MAX_OBSERVATIONS:
                    self.first_seen_versions.setdefault((identity, curr["version"]), curr_scan_date)
        if changes:
            self.recent_events_by_scan.append(_sample_events(changes, prev_scan_date, curr_scan_date, prev_outdated))
        return kinds

    def recent_events(self) -> list[DependencyUpdateEvent]:
        return list(islice(chain.from_iterable(reversed(self.recent_events_by_scan)), RECENT_UPDATES_LIMIT))


def select_primary_branch(
    activity: Mapping[str, BranchWindowActivity],
    default_branch: str | None,
    deleted_branches: Sequence[str] | None = None,
) -> str | None:
    """Busiest branch absent a comparable default, so a one-off feature-branch scan cannot hijack the project."""
    deleted = set(deleted_branches or ())
    live = {branch: seen for branch, seen in activity.items() if branch not in deleted}
    if not live:
        return None
    if default_branch in live and live[default_branch].commit_count >= MIN_COMPARABLE_BARS:
        return default_branch
    return max(live, key=lambda branch: (live[branch].commit_count, live[branch].last_scan_at, branch))


async def elect_primary_branch(
    scan_repo: ScanRepository,
    project_id: str,
    since: datetime | None,
    default_branch: str | None,
    deleted_branches: Sequence[str] | None,
) -> str | None:
    activity = await window_scans_by_branch(scan_repo, [project_id], since)
    return select_primary_branch(activity.get(project_id, {}), default_branch, deleted_branches)


def same_commit_runs[T](items: Sequence[T], *, commit_of: Callable[[T], str | None]) -> list[list[T]]:
    """A run merges scans into one bar but drops no pair, so sum(bar.updates_count) == total_updates."""
    runs: list[list[T]] = []
    for item in items:
        commit = commit_of(item)
        if runs and commit and commit_of(runs[-1][-1]) == commit:
            runs[-1].append(item)
        else:
            runs.append([item])
    return runs


def fold_runs_into_bars(entries: Sequence[ScanTimelineEntry], commits: Sequence[str | None]) -> list[ScanTimelineEntry]:
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


# A bar can hold a whole run, so over-fetch lest a CI retry burst starves the window below max_scans.
_BAR_FETCH_HEADROOM = 5

# The delta ledger's chain order, so both read paths cut a same-millisecond tie at the same scan.
WALK_SCAN_SORT: list[tuple[str, int]] = [("created_at", -1), ("_id", -1)]


def walk_fetch_limit(max_scans: int, since: datetime | None) -> int:
    """With since set, the calendar window (capped by WINDOW_HARD_LIMIT) applies and max_scans is ignored."""
    return WINDOW_HARD_LIMIT if since is not None else min(WINDOW_HARD_LIMIT, max_scans * _BAR_FETCH_HEADROOM)


async def _load_completed_scans(
    scan_repo: ScanRepository,
    project_id: str,
    branch: str,
    max_scans: int,
    since: datetime | None,
) -> tuple[list[dict[str, Any]], bool]:
    fetch_limit = walk_fetch_limit(max_scans, since)
    # Filtered in the query so the limit counts only usable scans, even when the newest ones failed.
    docs = await scan_repo.find_many_raw(
        {**usable_scan_match(since), "project_id": project_id, "branch": branch},
        sort=WALK_SCAN_SORT,
        limit=fetch_limit,
        projection={"_id": 1, "created_at": 1, "commit_hash": 1},
    )
    scans_raw: list[dict[str, Any]] = [
        {"_id": d["_id"], "created_at": d["created_at"], "commit_hash": d.get("commit_hash")} for d in docs
    ]
    scans_raw.reverse()
    if since is None:
        # Cap whole runs, so a retry storm cannot thin the window below max_scans bars.
        runs = same_commit_runs(scans_raw, commit_of=lambda scan: scan["commit_hash"])
        return [scan for run in runs[-max_scans:] for scan in run], False
    # A full fetch means older scans went unread, so the stretch folded is narrower than the window asked for.
    return scans_raw, len(docs) >= fetch_limit


def spanned_days(first: datetime, last: datetime) -> int:
    """Floored at one day so a burst cannot inflate a rate."""
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
    retention_days: int | None = None,
) -> UpdateFrequencyMetrics:
    """One branch only, since other branches' differences are no updates; only window_days yields a monthly rate."""
    if branch is None:
        return short_window([]).to_metrics(project_id, project_name)
    since = window_cutoff(window_days)

    completed_scans, truncated = await _load_completed_scans(scan_repo, project_id, branch, max_scans, since)

    state = _AccumulatorState(track_adoption=release_fetcher is not None)

    analysed: list[tuple[dict[str, Any], set[str] | None]] = []
    prev_deps: dict[str, dict[str, str]] = {}
    for curr_scan in completed_scans:
        curr_deps = await load_scan_deps(dep_repo, curr_scan["_id"])
        # An SBOM-less scan measured nothing, so it is dropped as in the delta ledger.
        if not curr_deps:
            continue
        state.accumulate_types(curr_deps)

        curr_outdated, curr_failed = await _load_outdated_for_scan(
            analysis_repo, curr_scan["_id"], state.package_latest_info
        )
        state.record_outdated(curr_outdated)

        kinds: Counter[str] = Counter()
        if analysed:
            prev_scan, prev_outdated = analysed[-1]
            state.record_resolved(prev_outdated, curr_outdated, curr_deps, curr_failed)
            kinds = state.absorb_changes(
                list(version_changes(prev_deps, curr_deps)),
                prev_scan["created_at"],
                curr_scan["created_at"],
                prev_outdated,
            )
        state.scan_timeline.append(
            _build_timeline_entry(curr_scan["_id"], curr_scan["created_at"], kinds, _measured_count(curr_outdated))
        )

        analysed.append((curr_scan, curr_outdated))
        prev_deps = curr_deps

    latest_outdated: set[str] = set()
    for run in same_commit_runs(analysed, commit_of=lambda member: member[0]["commit_hash"]):
        run_outdated = run[-1][1]
        state.record_bar_outdated(run_outdated)
        if run_outdated is not None:
            latest_outdated = run_outdated
    bars = fold_runs_into_bars(state.scan_timeline, [scan["commit_hash"] for scan, _outdated in analysed])

    if len(bars) < MIN_COMPARABLE_BARS:
        return short_window(bars).to_metrics(project_id, project_name, branch=branch)

    upstream = await _maybe_fetch_upstream_cadence(release_fetcher, state.package_specs, state.first_seen_versions)
    slowest_packages, outdated_backlog = _build_slowest_packages(
        state.package_outdated_counts,
        state.package_latest_info,
        state.dep_type_map,
        latest_outdated,
        _final_versions_by_name(prev_deps),
    )
    retained = None if truncated or window_days is None else retained_window(window_days, retention_days)
    # Past the cap the rate divides by the stretch the walk folded, not by a window it only partly saw.
    rate_days = (
        spanned_days(datetime.fromisoformat(bars[0].date), datetime.fromisoformat(bars[-1].date))
        if truncated
        else retained or window_days
    )
    folded = summarise_window(
        bars,
        state.type_counter,
        state.ever_outdated,
        state.ever_resolved,
        rate_days,
        dominant_ecosystem(Counter(info["type"] for info in prev_deps.values())),
    )
    return folded.to_metrics(
        project_id,
        project_name,
        branch=branch,
        slowest_packages=slowest_packages,
        recent_updates=state.recent_events(),
        upstream=upstream,
        window_scan_cap=WINDOW_HARD_LIMIT if truncated else None,
        retention_days=retained,
        outdated_backlog=outdated_backlog,
    )


# Half the browser's 30 s request timeout, so a slow deps.dev never costs the walk its own answer.
_UPSTREAM_BUDGET_SECONDS = 15.0


async def _maybe_fetch_upstream_cadence(
    release_fetcher: ReleaseHistoryFetcher | None,
    package_specs: dict[str, tuple[str, str]],
    first_seen_versions: dict[tuple[str, str], datetime],
) -> UpstreamCadenceMetrics | None:
    """Supplementary: failures and a missing fetcher yield None so the rest of the report still ships."""
    if release_fetcher is None or not package_specs:
        return None

    try:
        async with asyncio.timeout(_UPSTREAM_BUDGET_SECONDS):
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


def placeholder_summary(
    project: dict[str, Any], status: UpdateDataStatus, window_days: int, branch: str | None = None
) -> ProjectUpdateSummary:
    """A row without numbers, naming the branch it looked at, so every project stays accounted for once."""
    return ProjectUpdateSummary(
        project_id=str(project["_id"]),
        project_name=project.get("name", ""),
        teams=project.get("teams") or [],
        data_status=status,
        branch=branch,
        window_days=window_days,
    )


def measured_summary(
    metrics: UpdateFrequencyMetrics,
    teams: list[TeamRef],
    *,
    window_days: int,
    data_status: Literal["ready", "partial"] = "ready",
) -> ProjectUpdateSummary:
    """data_status comes from CommitCoverage: the fold knows what it summed, not what the window held."""
    return ProjectUpdateSummary(
        project_id=metrics.project_id,
        project_name=metrics.project_name,
        teams=teams,
        data_status=data_status,
        branch=metrics.branch,
        window_days=window_days,
        scan_count=metrics.scan_count,
        updates_per_month=metrics.updates_per_month,
        update_coverage_pct=metrics.update_coverage_pct,
        patch_ratio=metrics.granularity_ratio.get("patch", 0.0),
        trend_direction=metrics.trend_direction,
        total_updates=metrics.total_updates,
        total_outdated=metrics.total_outdated_detected,
        last_scan_date=metrics.last_scan_date,
        window_scan_cap=metrics.window_scan_cap,
        retention_days=metrics.retention_days,
    )


def _rate(summary: ProjectUpdateSummary) -> float:
    return summary.updates_per_month if summary.updates_per_month is not None else -1.0


def _name_key(summary: ProjectUpdateSummary) -> tuple[str, str]:
    return case_insensitive_key(summary.project_name)


def rank_summaries(summaries: list[ProjectUpdateSummary]) -> UpdateFrequencyComparison:
    """Unmeasured rows are named, not counted, so a reader can go and look at them."""
    ready = [s for s in summaries if s.data_status == "ready"]
    partial = sorted((s for s in summaries if s.data_status == "partial"), key=lambda s: (-_rate(s), _name_key(s)))
    pending = sorted((s for s in summaries if s.data_status == "pending"), key=_name_key)
    thin = sorted((s for s in summaries if s.data_status == "insufficient_data"), key=_name_key)
    failed = sorted((s for s in summaries if s.data_status == "error"), key=_name_key)

    measured = [s for s in ready if s.update_coverage_pct is not None]
    unmeasured = [s for s in ready if s.update_coverage_pct is None]
    measured.sort(key=lambda s: (-(s.update_coverage_pct or 0.0), -_rate(s), _name_key(s)))
    unmeasured.sort(key=lambda s: (-_rate(s), _name_key(s)))

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
    window_days: int = UPDATE_FREQUENCY_COMPARISON_WINDOW_DAYS,
) -> UpdateFrequencyComparison:
    """One calendar window for every project: different spans would rank scan cadence, not update activity."""
    # Per call: a Semaphore binds to the loop of first use, so a module-level one would pin to the first loop.
    semaphore = asyncio.Semaphore(_COMPARISON_CONCURRENCY)
    since = window_cutoff(window_days)

    activity = await window_scans_by_branch(scan_repo, [str(p["_id"]) for p in projects], since)

    async def _compute_single(project: dict[str, Any]) -> ProjectUpdateSummary:
        project_id = str(project["_id"])
        primary: str | None = None
        try:
            branches = activity.get(project_id, {})
            primary = select_primary_branch(branches, project.get("default_branch"), project.get("deleted_branches"))
            # The window holds every scan the walk would read, so one commit can only ever fold into one bar.
            if primary is None or branches[primary].commit_count < MIN_COMPARABLE_BARS:
                return placeholder_summary(project, "insufficient_data", window_days, primary)

            async with semaphore:
                metrics = await compute_update_frequency(
                    project_id=project_id,
                    project_name=project.get("name", ""),
                    scan_repo=scan_repo,
                    dep_repo=dep_repo,
                    analysis_repo=analysis_repo,
                    window_days=window_days,
                    branch=primary,
                    retention_days=project.get("retention_horizon"),
                )
            if metrics.scan_count < MIN_COMPARABLE_BARS:
                return placeholder_summary(project, "insufficient_data", window_days, primary)
            # The walk reads the very scans coverage is measured against, so it cannot lag like the delta ledger.
            return measured_summary(metrics, project.get("teams") or [], window_days=window_days)
        except Exception:
            logger.warning(f"Failed to compute update frequency for project {project_id}", exc_info=True)
            return placeholder_summary(project, "error", window_days, primary)

    return rank_summaries(await asyncio.gather(*[_compute_single(p) for p in projects]))
