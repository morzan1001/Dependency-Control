from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import dropwhile
from typing import Any, Literal, get_args

from app.core.constants import COUNTED_UPDATE_KINDS, UpdateKind
from app.schemas.analytics import ScanTimelineEntry
from app.services.update_frequency import (
    FoldedWindow,
    fold_runs_into_bars,
    same_commit_runs,
    short_window,
    summarise_window,
    window_coverage_status,
)

logger = logging.getLogger(__name__)


def select_window(deltas: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Input must be one project's one branch, oldest first; the anchor window[0] contributes no update counts."""
    usable = [d for d in deltas if int(d.get("dep_count", 0)) > 0 and not d.get("error")]
    return _contiguous_tail(usable)


def window_bars(window: Sequence[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    return same_commit_runs(window, commit_of=lambda delta: delta.get("commit_hash"))


def _commit_token(delta: dict[str, Any]) -> str:
    """A scan that names no commit stands for itself."""
    token: str = delta.get("commit_hash") or delta["_id"]
    return token


@dataclass(frozen=True)
class CommitCoverage:
    accounted: int
    coverable: int

    @property
    def status(self) -> Literal["ready", "partial"]:
        return window_coverage_status(self.accounted, self.coverable)


def commit_coverage(
    deltas: Sequence[dict[str, Any]], window: Sequence[dict[str, Any]], scans_per_commit: Mapping[str, int]
) -> CommitCoverage:
    """Counts commits, not documents, so a CI retry storm does not read as missing data."""
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
    """baseline_outdated is window[0]'s outdated set, None without an analysis; window_days is None for a scan count."""
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
    return summarise_window(timeline, kinds, ever_outdated, ever_resolved, window_days, ecosystem=None)


def _contiguous_tail(deltas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A link that skips a scan breaks the tiling and would count an interval twice, so the window truncates there."""
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
    """Summed unconditionally: the writer already empties the lists where a comparison lacked a measurement."""
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
