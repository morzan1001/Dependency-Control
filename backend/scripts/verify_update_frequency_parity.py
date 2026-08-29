"""Compare the live update-frequency read path against the delta ledger, field by field.

This is the gate for flipping UPDATE_FREQUENCY_USE_ROLLUP, so it checks both reads that flag
switches: the cross-project comparison endpoint — every row field, the row order and the
aggregate counters — and the per-project metrics behind the project page.

No deviation is excused by project. Both paths select the same scans by the same rules, so
every scan only one of them folded is a gap in the ledger and is named with what the ledger
holds for it — an unwritten delta, a writer failure, or a delta the fold left out. Those are
what the backfill is for.

Deviations that are not a scan-set difference
---------------------------------------------
* `recent_updates`. The writer keeps at most 20 samples per scan while the live path buffers
  the newest 30 events overall, so a scan with more than 20 updates — or a live list that hit
  its 30-event cap mid-scan — leaves the two with different events. Order inside one scan is
  Mongo document order on the live side and sorted on the ledger side, so the comparison is
  by set.
* `dominant_ecosystem`. The live path folds the dependency types of every scan in the window,
  the ledger reports what the newest scan holds.
* `slowest_packages` once the list hits its 15-entry cap: neither path defines a tie-break
  for the packages sitting on that boundary.

The deps.dev cadence fields are not compared: neither path fetches release history here.

Both checks run over the sampled projects only, so the comparison's ranking and averages are
the sample's. `--sample 1000` covers every project with two usable scans in the window.

Usage (in-pod): `python -m scripts.verify_update_frequency_parity --help` from /app.

Exit codes:
    0 — every field agreed, or only deviations with a named cause
    1 — connection or runtime error
    2 — at least one deviation without a named cause
    3 — the sample was empty, so nothing was compared
"""

import argparse
import asyncio
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from motor.motor_asyncio import AsyncIOMotorClient

from app.api.v1.endpoints.analytics.update_frequency import (
    _DEFAULT_COMPARISON_WINDOW_DAYS,
    _SLOWEST_PACKAGES_LIMIT,
    _compute_comparison,
    _compute_comparison_from_rollup,
    _rollup_project_metrics,
)
from app.core.config import settings
from app.core.constants import SCAN_USABLE_STATUSES
from app.repositories import AnalysisResultRepository, DependencyRepository, ScanRepository
from app.schemas.analytics import UpdateFrequencyMetrics
from app.services.update_frequency import (
    compute_update_frequency,
    window_cutoff,
)
from app.services.update_frequency_fold import _RECENT_UPDATES_LIMIT
from app.services.update_frequency_rollup import _UPDATES_SAMPLE_CAP

DEFAULT_SAMPLE = 20

_PROJECT_PROJECTION = {"_id": 1, "name": 1, "default_branch": 1, "deleted_branches": 1}

# The 20 metric fields both paths compute from the same history.
_SCALAR_FIELDS = (
    "branch",
    "scan_count",
    "time_range_days",
    "first_scan_date",
    "last_scan_date",
    "total_updates",
    "updates_per_scan",
    "updates_per_month",
    "patch_updates",
    "minor_updates",
    "major_updates",
    "unknown_updates",
    "downgrade_updates",
    "granularity_ratio",
    "avg_days_between_scans",
    "total_outdated_detected",
    "outdated_resolved",
    "update_coverage_pct",
    "trend_direction",
    "trend_detail",
)

# Everything a comparison row shows.
_SUMMARY_FIELDS = (
    "project_name",
    "team_name",
    "data_status",
    "branch",
    "window_days",
    "scan_count",
    "updates_per_month",
    "update_coverage_pct",
    "patch_ratio",
    "trend_direction",
    "total_updates",
    "total_outdated",
    "last_scan_date",
)

_COMPARISON_TOTAL_FIELDS = (
    "team_avg_updates_per_month",
    "team_avg_coverage_pct",
    "best_project",
    "worst_project",
    "partial_projects",
    "pending_projects",
    "skipped_insufficient_data",
    "skipped_error",
)

_ROW_ORDER_FIELD = "row order"

_SAMPLE_CAP_REASON = f"the writer keeps at most {_UPDATES_SAMPLE_CAP} samples per scan"
_SATURATED_REASON = f"the live list hit its {_RECENT_UPDATES_LIMIT}-event cap, so the two truncate differently"
_ECOSYSTEM_REASON = "the live path folds every scan's dependency types, the ledger the newest scan's"
_SLOWEST_CAP_REASON = f"the list hit its {_SLOWEST_PACKAGES_LIMIT}-entry cap, whose tie-break neither path defines"

_ABSENCE_NO_DELTA = "no delta written yet"
_ABSENCE_WRITER_ERROR = "its delta records a writer failure"
_ABSENCE_STALE_DEP_COUNT = "its delta records no dependencies although the scan carries some"
_ABSENCE_NOT_FOLDED = "its delta was left out of the folded window"

# Long scan lists say nothing more than short ones about the cause.
_NAMED_SCANS_CAP = 6


@dataclass(frozen=True)
class Deviation:
    field: str
    live: Any
    rollup: Any
    reason: str | None = None
    project_id: str | None = None

    @property
    def key(self) -> tuple[str | None, str]:
        return self.project_id, self.field


@dataclass(frozen=True)
class KnownCauses:
    """Conditions under which one named field is meant to differ between the paths."""

    capped_sample_scans: int
    live_updates_saturated: bool
    slowest_packages_capped: bool

    def reason_for(self, field: str) -> str | None:
        if field == "dominant_ecosystem":
            return _ECOSYSTEM_REASON
        if field == "recent_updates":
            if self.capped_sample_scans:
                return _SAMPLE_CAP_REASON
            if self.live_updates_saturated:
                return _SATURATED_REASON
        if field == "slowest_packages" and self.slowest_packages_capped:
            return _SLOWEST_CAP_REASON
        return None


@dataclass(frozen=True)
class ScanSetDiff:
    """Scans one path folded and the other did not, with why the ledger holds no usable delta."""

    live_only: tuple[tuple[str, str], ...] = ()
    rollup_only: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.live_only or self.rollup_only)

    def describe(self) -> str:
        named = [f"{scan_id} ({why})" for scan_id, why in self.live_only[:_NAMED_SCANS_CAP]]
        named += [f"{scan_id} (folded only by the ledger)" for scan_id in self.rollup_only[:_NAMED_SCANS_CAP]]
        rest = max(0, len(self.live_only) - _NAMED_SCANS_CAP) + max(0, len(self.rollup_only) - _NAMED_SCANS_CAP)
        tail = f", and {rest} more" if rest else ""
        return f"the paths folded different scans: {', '.join(named)}{tail}"


@dataclass(frozen=True)
class ProjectReport:
    project_id: str
    project_name: str
    branch: str | None
    deviations: tuple[Deviation, ...]
    scan_diff: ScanSetDiff = ScanSetDiff()
    declined: str | None = None

    @property
    def unexplained(self) -> tuple[Deviation, ...]:
        return tuple(d for d in self.deviations if d.reason is None)


def _timeline_signature(metrics: UpdateFrequencyMetrics) -> list[tuple[Any, ...]]:
    return [
        (e.scan_id, e.date, e.updates_count, e.outdated_count, e.patch, e.minor, e.major, e.unknown, e.downgrades)
        for e in metrics.scan_timeline
    ]


def _updates_signature(metrics: UpdateFrequencyMetrics) -> set[tuple[Any, ...]]:
    return {
        (
            e.package_name,
            e.old_version,
            e.new_version,
            e.update_type,
            e.scan_date,
            e.previous_scan_date,
            e.days_between_scans,
            e.was_outdated,
        )
        for e in metrics.recent_updates
    }


def _slowest_signature(metrics: UpdateFrequencyMetrics) -> set[tuple[Any, ...]]:
    return {(p.name, p.type, p.current_version, p.latest_version, p.scans_outdated) for p in metrics.slowest_packages}


def compare_metrics(
    live: UpdateFrequencyMetrics, rollup: UpdateFrequencyMetrics, causes: KnownCauses
) -> list[Deviation]:
    """Every metrics field the two paths disagree on, each tagged with its named cause or None."""
    pairs: list[tuple[str, Any, Any]] = [
        (field, getattr(live, field), getattr(rollup, field)) for field in _SCALAR_FIELDS
    ]
    pairs.append(("dominant_ecosystem", live.dominant_ecosystem, rollup.dominant_ecosystem))
    pairs.append(("scan_timeline", _timeline_signature(live), _timeline_signature(rollup)))
    pairs.append(("recent_updates", _updates_signature(live), _updates_signature(rollup)))
    pairs.append(("slowest_packages", _slowest_signature(live), _slowest_signature(rollup)))
    return [
        Deviation(field=field, live=live_value, rollup=rollup_value, reason=causes.reason_for(field))
        for field, live_value, rollup_value in pairs
        if live_value != rollup_value
    ]


def compare_comparisons(live: dict[str, Any], rollup: dict[str, Any]) -> list[Deviation]:
    """Every row field, the row order and every counter the two comparison payloads disagree on."""
    live_rows = {row["project_id"]: row for row in live["projects"]}
    rollup_rows = {row["project_id"]: row for row in rollup["projects"]}
    live_order = [row["project_id"] for row in live["projects"]]
    rollup_order = [row["project_id"] for row in rollup["projects"]]

    deviations = [
        Deviation(
            field=field,
            live=live_rows[project_id][field],
            rollup=rollup_rows[project_id][field],
            project_id=project_id,
        )
        for project_id in live_order
        if project_id in rollup_rows
        for field in _SUMMARY_FIELDS
        if live_rows[project_id][field] != rollup_rows[project_id][field]
    ]
    if live_order != rollup_order:
        deviations.append(Deviation(field=_ROW_ORDER_FIELD, live=live_order, rollup=rollup_order))
    deviations.extend(
        Deviation(field=field, live=live[field], rollup=rollup[field])
        for field in _COMPARISON_TOTAL_FIELDS
        if live[field] != rollup[field]
    )
    return deviations


async def known_causes(
    db: Any, project_id: str, branch: str | None, since: datetime, live: UpdateFrequencyMetrics
) -> KnownCauses:
    docs = await db.scan_update_deltas.find(
        {"project_id": project_id, "branch": branch, "scan_created_at": {"$gte": since}},
        {"updates": 1},
    ).to_list(None)
    # The sample array is written before the cap, so its pre-cap length is the full update count.
    capped = sum(1 for doc in docs if sum((doc.get("updates") or {}).values()) > _UPDATES_SAMPLE_CAP)
    return KnownCauses(
        capped_sample_scans=capped,
        live_updates_saturated=len(live.recent_updates) >= _RECENT_UPDATES_LIMIT,
        slowest_packages_capped=len(live.slowest_packages) >= _SLOWEST_PACKAGES_LIMIT,
    )


async def scan_set_diff(db: Any, live: UpdateFrequencyMetrics, rollup: UpdateFrequencyMetrics) -> ScanSetDiff:
    """Which scans only one path folded, and why the ledger has no usable delta for each."""
    live_ids = [entry.scan_id for entry in live.scan_timeline]
    rollup_ids = {entry.scan_id for entry in rollup.scan_timeline}
    missing = [scan_id for scan_id in live_ids if scan_id not in rollup_ids]

    docs = await db.scan_update_deltas.find({"_id": {"$in": missing}}, {"dep_count": 1, "error": 1}).to_list(None)
    deltas = {doc["_id"]: doc for doc in docs}

    def _why(scan_id: str) -> str:
        doc = deltas.get(scan_id)
        if doc is None:
            return _ABSENCE_NO_DELTA
        if doc.get("error"):
            return _ABSENCE_WRITER_ERROR
        if not doc.get("dep_count"):
            return _ABSENCE_STALE_DEP_COUNT
        return _ABSENCE_NOT_FOLDED

    return ScanSetDiff(
        live_only=tuple((scan_id, _why(scan_id)) for scan_id in missing),
        rollup_only=tuple(scan_id for scan_id in rollup_ids if scan_id not in set(live_ids)),
    )


async def _live_metrics(db: Any, project: dict[str, Any], window_days: int) -> UpdateFrequencyMetrics:
    return await compute_update_frequency(
        project_id=str(project["_id"]),
        project_name=project.get("name", ""),
        scan_repo=ScanRepository(db),
        dep_repo=DependencyRepository(db),
        analysis_repo=AnalysisResultRepository(db),
        window_days=window_days,
        deleted_branches=project.get("deleted_branches"),
        default_branch=project.get("default_branch"),
    )


async def _decline_reason(db: Any, project_id: str, branch: str | None, since: datetime) -> str:
    """What the ledger holds for the branch it could not answer for, so the gap is actionable."""
    docs = await db.scan_update_deltas.find(
        {"project_id": project_id, "branch": branch or "", "scan_created_at": {"$gte": since}},
        {"dep_count": 1, "error": 1},
    ).to_list(None)
    foldable = sum(1 for doc in docs if doc.get("dep_count") and not doc.get("error"))
    failed = sum(1 for doc in docs if doc.get("error"))
    return f"{len(docs)} delta(s) in the window, {foldable} foldable, {failed} holding a writer failure"


async def verify_project(db: Any, project: dict[str, Any], window_days: int) -> ProjectReport:
    project_id = str(project["_id"])
    project_name = project.get("name", "")
    since = cast(datetime, window_cutoff(window_days))

    live = await _live_metrics(db, project, window_days)
    rollup = await _rollup_project_metrics(db, project, window_days)
    if rollup is None:
        return ProjectReport(
            project_id=project_id,
            project_name=project_name,
            branch=live.branch,
            deviations=(),
            declined=await _decline_reason(db, project_id, live.branch, since),
        )

    causes = await known_causes(db, project_id, rollup.branch, since, live)
    return ProjectReport(
        project_id=project_id,
        project_name=project_name,
        branch=rollup.branch,
        deviations=tuple(compare_metrics(live, rollup, causes)),
        scan_diff=await scan_set_diff(db, live, rollup),
    )


async def verify_comparison(db: Any, project_ids: list[str], window_days: int) -> list[Deviation]:
    """The two comparison payloads over the same projects, row for row, in order, with counters."""
    live = await _compute_comparison(db, project_ids, None, window_days=window_days)
    rollup = await _compute_comparison_from_rollup(db, project_ids, None, window_days=window_days)
    return compare_comparisons(live, rollup)


async def select_projects(db: Any, *, sample: int, project_id: str | None, since: datetime) -> list[dict[str, Any]]:
    """Projects to compare: one named project, else the busiest ones with something to compare.

    Ranking by in-window scan count is deterministic, so a rerun after a fix looks at the same
    projects; it does bias the sample towards the histories most likely to hit the sample caps.
    """
    if project_id:
        project = await db.projects.find_one({"_id": project_id}, _PROJECT_PROJECTION)
        return [project] if project else []

    rows = await db.scans.aggregate(
        [
            {
                "$match": {
                    "created_at": {"$gte": since},
                    "status": {"$in": SCAN_USABLE_STATUSES},
                    "is_rescan": {"$ne": True},
                }
            },
            {"$group": {"_id": "$project_id", "scans": {"$sum": 1}}},
            # A single scan supports no comparison, so such a project proves nothing either way.
            {"$match": {"scans": {"$gte": 2}}},
            {"$sort": {"scans": -1, "_id": 1}},
            {"$limit": sample},
        ]
    ).to_list(None)

    ranked = [row["_id"] for row in rows]
    docs = await db.projects.find({"_id": {"$in": ranked}}, _PROJECT_PROJECTION).to_list(len(ranked))
    by_id = {str(doc["_id"]): doc for doc in docs}
    return [by_id[pid] for pid in ranked if pid in by_id]


def _render(value: Any) -> str:
    if isinstance(value, set):
        return f"{len(value)} entries"
    text = repr(value)
    return text if len(text) <= 160 else f"{text[:157]}..."


def _print_set_members(deviation: Deviation, indent: str) -> None:
    """The entries behind an "N entries" line, so a set deviation names what moved."""
    if not (isinstance(deviation.live, set) and isinstance(deviation.rollup, set)):
        return
    for side, entries in (
        ("live only", deviation.live - deviation.rollup),
        ("rollup only", deviation.rollup - deviation.live),
    ):
        for entry in sorted(entries, key=repr):
            print(f"{indent}  {side}: {entry}")


def _print_deviations(deviations: Iterable[Deviation], indent: str, *, cause_already_shown: str | None = None) -> None:
    """One line per deviation; a cause repeated from the line above is not spelled out again."""
    previous = cause_already_shown
    for deviation in deviations:
        label = "known   " if deviation.reason else "MISMATCH"
        live, rollup = _render(deviation.live), _render(deviation.rollup)
        print(f"{indent}{label} {deviation.field:<24} live={live}  rollup={rollup}")
        _print_set_members(deviation, indent)
        if deviation.reason:
            print(f"{indent}  cause: {'as above' if deviation.reason == previous else deviation.reason}")
        previous = deviation.reason


def print_comparison_report(deviations: Sequence[Deviation], names: Mapping[str, str]) -> None:
    print("== comparison endpoint ==")
    if not deviations:
        print("  every row field, the row order and every counter agree")
        return
    for project_id in dict.fromkeys(d.project_id for d in deviations if d.project_id):
        print(f"  [{project_id} / {names.get(str(project_id), '')}]")
        _print_deviations((d for d in deviations if d.project_id == project_id), indent="    ")
    _print_deviations((d for d in deviations if d.project_id is None), indent="  ")


def print_project_report(reports: Sequence[ProjectReport]) -> None:
    print("== per-project metrics ==")
    for report in reports:
        header = f"  [{report.project_id} / {report.project_name}] branch={report.branch}"
        if report.declined:
            print(f"{header} — the ledger declined this project ({report.declined}); the endpoint falls back to live")
            continue
        if not report.deviations:
            print(f"{header} — identical on every field")
            continue
        print(header)
        shown = None
        if report.scan_diff:
            shown = report.scan_diff.describe()
            print(f"    scans: {shown}")
        _print_deviations(report.deviations, indent="    ", cause_already_shown=shown)


def print_totals(reports: Sequence[ProjectReport], comparison: Sequence[Deviation], window_days: int) -> None:
    compared = [r for r in reports if r.declined is None]
    unexplained = [r for r in compared if r.unexplained]
    known_only = [r for r in compared if r.deviations and not r.unexplained]
    print()
    print(f"window: {window_days} day(s)")
    print(f"projects sampled:            {len(reports)}")
    print(f"  identical on every field:  {len(compared) - len(unexplained) - len(known_only)}")
    print(f"  only known deviations:     {len(known_only)}")
    print(f"  unexplained deviations:    {len(unexplained)}")
    print(f"  ledger declined:           {len(reports) - len(compared)}")
    print(f"comparison deviations:       {len(comparison)}")
    print(f"  unexplained:               {sum(1 for d in comparison if d.reason is None)}")


async def run(args: argparse.Namespace) -> int:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.MONGODB_URL)
    try:
        db = client[settings.DATABASE_NAME]
        since = cast(datetime, window_cutoff(args.window_days))
        projects = await select_projects(db, sample=args.sample, project_id=args.project_id, since=since)
        if not projects:
            print("No project with at least two usable scans in the window; nothing compared.", file=sys.stderr)
            return 3

        reports = [await verify_project(db, project, args.window_days) for project in projects]
        comparison = await verify_comparison(db, [str(p["_id"]) for p in projects], args.window_days)

        print_comparison_report(comparison, {r.project_id: r.project_name for r in reports})
        print()
        print_project_report(reports)
        print_totals(reports, comparison, args.window_days)

        drifted = any(report.unexplained for report in reports) or any(d.reason is None for d in comparison)
        return 2 if drifted else 0
    except Exception as exc:
        print(f"verify_update_frequency_parity: ERROR — {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--sample",
        type=int,
        default=DEFAULT_SAMPLE,
        help=f"Projects to compare, busiest first (default: {DEFAULT_SAMPLE}).",
    )
    parser.add_argument(
        "--project-id",
        help="Compare exactly this project instead of a sample.",
    )
    parser.add_argument(
        "--window-days",
        type=int,
        default=_DEFAULT_COMPARISON_WINDOW_DAYS,
        help=f"Calendar window both paths analyse (default: {_DEFAULT_COMPARISON_WINDOW_DAYS}).",
    )
    args = parser.parse_args()

    if args.sample < 1:
        parser.error("--sample must be >= 1")
    if args.window_days < 1:
        parser.error("--window-days must be >= 1")

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
