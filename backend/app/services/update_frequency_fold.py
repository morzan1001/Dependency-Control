"""Project-level update-frequency metrics folded from per-scan delta documents."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import dropwhile, pairwise
from typing import Any, Literal, get_args

from app.core.constants import COUNTED_UPDATE_KINDS, UpdateKind
from app.schemas.analytics import ScanTimelineEntry
from app.services.update_frequency import (
    FoldedWindow,
    dominant_ecosystem,
    fold_runs_into_bars,
    same_commit_runs,
    short_window,
    summarise_window,
    window_coverage_status,
)

logger = logging.getLogger(__name__)


def select_window(deltas: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Narrow ``scan_update_deltas`` docs of one branch to a window that can be summed.

    Input must be one project, one branch, oldest first — a reversed or
    branch-mixed window would otherwise fold into negative cadences and
    cross-branch version differences counted as updates.

    SBOM-less scans and writer failures drop out: a missing measurement is
    not a measurement of zero, and keeping it would add a structural
    zero-update bar. ``window[0]`` is the anchor: its update counts are dropped
    because they compare against a scan outside the window, while its id, date
    and outdated count still enter the fold.
    """
    _reject_broken_contract(deltas)
    usable = [d for d in deltas if int(d.get("dep_count", 0)) > 0 and not d.get("error")]
    return _contiguous_tail(usable)


def window_bars(window: Sequence[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """The window's same-commit runs: one timeline bar each."""
    return same_commit_runs(window, commit_of=lambda delta: delta.get("commit_hash"))


def _commit_token(delta: dict[str, Any]) -> str:
    """A scan that names no commit stands for itself."""
    token: str = delta.get("commit_hash") or delta["_id"]
    return token


@dataclass(frozen=True)
class CommitCoverage:
    """How much of a branch's window the ledger accounted for, in commits."""

    accounted: int
    coverable: int

    @property
    def status(self) -> Literal["ready", "partial"]:
        return window_coverage_status(self.accounted, self.coverable)


def commit_coverage(
    deltas: Sequence[dict[str, Any]], window: Sequence[dict[str, Any]], scans_per_commit: Mapping[str, int]
) -> CommitCoverage:
    """What ``select_window(deltas)`` reached of the commits its branch window holds.

    Both sides count commits rather than documents, or a CI retry storm would read as
    missing data. A commit leaves both sides only when the ledger proves nobody could
    measure it: every one of its scans in the window carries a delta, and every one of
    those reports no dependencies and no writer failure. One scan of it still owing a
    delta is a hole, a failure is a hole, and so is everything before the window's
    anchor, which the fold could not reach.

    Both sides are keyed on the same token set, the one the scan side counted. A delta
    whose scan is no longer in the window -- an orphan the nightly reconcile has yet to
    remove -- can therefore neither shrink the denominator nor pad the numerator.
    """
    measured: dict[str, int] = {}
    unmeasurable: dict[str, int] = {}
    for delta in deltas:
        token = _commit_token(delta)
        if token not in scans_per_commit:
            continue
        bucket = measured if (delta.get("error") or int(delta.get("dep_count", 0))) else unmeasurable
        bucket[token] = bucket.get(token, 0) + 1

    skipped = {
        token for token, seen in unmeasurable.items() if token not in measured and seen >= scans_per_commit[token]
    }

    covered = dropwhile(lambda delta: delta["_id"] != window[0]["_id"], deltas)
    accounted = {
        _commit_token(d) for d in covered if not d.get("error") and _commit_token(d) in scans_per_commit
    } - skipped
    return CommitCoverage(len(accounted), len(scans_per_commit) - len(skipped))


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
    per_scan = [_timeline_entry(window[0], baseline=True)] if window else []
    per_scan.extend(_timeline_entry(delta, baseline=False) for delta in window[1:])
    timeline = fold_runs_into_bars(per_scan, [delta.get("commit_hash") for delta in window])
    if len(timeline) < 2:
        return short_window(timeline)

    kinds: Counter[str] = Counter()
    for delta in window[1:]:
        updates = delta.get("updates") or {}
        for kind in get_args(UpdateKind):
            kinds[kind] += int(updates.get(kind, 0))

    ever_outdated, ever_resolved = _outdated_movement(window, baseline_outdated)
    return summarise_window(
        timeline, kinds, ever_outdated, ever_resolved, window_days, dominant_ecosystem(window[-1].get("eco") or {})
    )


def _reject_broken_contract(deltas: Sequence[dict[str, Any]]) -> None:
    """Guard the two mixups that silently produce plausible-looking wrong numbers."""
    scopes = {(d["project_id"], d["branch"]) for d in deltas}
    if len(scopes) > 1:
        raise ValueError(f"deltas span more than one project/branch: {sorted(scopes)}")
    for older, newer in pairwise(deltas):
        if newer["scan_created_at"] < older["scan_created_at"]:
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


def _timeline_entry(delta: dict[str, Any], *, baseline: bool) -> ScanTimelineEntry:
    updates: dict[str, Any] = {} if baseline else (delta.get("updates") or {})
    counts = {kind: int(updates.get(kind, 0)) for kind in COUNTED_UPDATE_KINDS}
    outdated_count = delta.get("outdated_count")
    return ScanTimelineEntry(
        scan_id=str(delta["_id"]),
        date=delta["scan_created_at"].isoformat(),
        updates_count=sum(counts.values()),
        outdated_count=None if outdated_count is None else int(outdated_count),
        patch=counts["patch"],
        minor=counts["minor"],
        major=counts["major"],
        unknown=counts["unknown"],
        downgrades=int(updates.get("downgrade", 0)),
    )
