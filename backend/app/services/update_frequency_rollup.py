"""Both dependency sets are read straight from dependencies, so a recomputation reproduces the same document."""

import logging
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from app.core.config import settings
from app.core.log_utils import sanitize_for_log
from app.core.metrics import update_frequency_delta_writes_total
from app.models.update_frequency import ScanOutdatedSet, ScanUpdateDelta, UpdateCounts
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.scans import is_usable_build
from app.repositories.update_frequency import ScanOutdatedSetRepository, ScanUpdateDeltaRepository
from app.services.update_frequency import load_outdated_entries, load_scan_deps, resolved_outdated, version_changes

logger = logging.getLogger(__name__)

_SCAN_PROJECTION = {
    "project_id": 1,
    "branch": 1,
    "created_at": 1,
    "commit_hash": 1,
    "status": 1,
    "is_rescan": 1,
}

_ERROR_MESSAGE_CAP = 300
_STALE_DEPENDENCIES_ERROR = "StaleDelta: the scan's dependencies changed after this delta was written"
_MAX_REPAIR_HOPS = 5


@dataclass(frozen=True)
class _ScanRef:
    scan_id: str
    project_id: str
    branch: str
    created_at: datetime
    commit_hash: str | None
    usable: bool


@dataclass
class _Diff:
    counts: Counter = field(default_factory=Counter)
    outdated_added: list[str] = field(default_factory=list)
    outdated_resolved: list[str] = field(default_factory=list)

    def to_counts(self) -> UpdateCounts:
        return UpdateCounts(**self.counts)


async def record_scan_update_delta(db: Any, scan_id: str) -> bool:
    """True once the scan's delta is written; never raises, as the ingest or restore would treat that as a lost scan."""
    try:
        if not settings.UPDATE_FREQUENCY_ROLLUP_ENABLED:
            return False
        delta = await _record(db, scan_id)
        # An SBOM-less scan is never a predecessor, so no later delta can be stale because of it.
        if delta is not None and delta.dep_count > 0:
            await _repair_successors(
                db,
                delta.project_id,
                delta.branch,
                delta.scan_created_at,
                delta.id,
                only_when_linked=False,
            )
    except Exception:
        logger.exception("Update-frequency rollup aborted for scan %s", sanitize_for_log(scan_id))
        update_frequency_delta_writes_total.labels(result="error").inc()
        return False
    return delta is not None


async def _record(db: Any, scan_id: str) -> ScanUpdateDelta | None:
    scan = await _load_scan(db, scan_id)
    if scan is None:
        return None
    if scan.usable:
        return await _compute_and_persist(db, scan)

    await _discard_delta(db, scan)
    return None


async def _compute_and_persist(db: Any, scan: _ScanRef) -> ScanUpdateDelta | None:
    try:
        delta, outdated = await _compute_delta(db, scan)
        await _persist(db, delta, outdated)
    except Exception as exc:
        logger.exception("Update-frequency delta failed for scan %s", scan.scan_id)
        update_frequency_delta_writes_total.labels(result="error").inc()
        try:
            await _save_error_delta(db, scan, f"{type(exc).__name__}: {exc}")
        except Exception as save_exc:
            logger.warning("Could not store the error delta of scan %s either: %s", scan.scan_id, save_exc)
        return None

    update_frequency_delta_writes_total.labels(result="ok").inc()
    return delta


async def _load_scan(db: Any, scan_id: str) -> _ScanRef | None:
    doc = await db.scans.find_one({"_id": scan_id}, _SCAN_PROJECTION)
    if doc is None:
        return None
    created_at = doc.get("created_at")
    if not isinstance(created_at, datetime):
        logger.warning("Scan %s has no usable created_at; skipping its update delta", sanitize_for_log(scan_id))
        return None
    return _ScanRef(
        scan_id=scan_id,
        project_id=doc.get("project_id", ""),
        branch=doc.get("branch", ""),
        created_at=created_at,
        commit_hash=doc.get("commit_hash"),
        usable=is_usable_build(doc),
    )


async def _compute_delta(db: Any, scan: _ScanRef) -> tuple[ScanUpdateDelta, set[str] | None]:
    deps = await load_scan_deps(DependencyRepository(db), scan.scan_id)
    if not deps:
        # Never a predecessor and never folded, so a comparison or outdated set of it would go unread.
        sbom_less = ScanUpdateDelta(
            id=scan.scan_id,
            project_id=scan.project_id,
            branch=scan.branch,
            scan_created_at=scan.created_at,
            commit_hash=scan.commit_hash,
            dep_count=0,
        )
        return sbom_less, None
    outdated, failed = await _load_outdated(db, scan.scan_id)

    prev, prev_deps = await _resolve_predecessor(db, scan)
    if prev is None:
        diff = _Diff()
    else:
        prev_outdated = (await ScanOutdatedSetRepository(db).names_by_scan([prev["_id"]])).get(prev["_id"])
        diff = _diff_scans(prev_deps, deps, prev_outdated, outdated, failed)

    delta = ScanUpdateDelta(
        id=scan.scan_id,
        project_id=scan.project_id,
        branch=scan.branch,
        scan_created_at=scan.created_at,
        commit_hash=scan.commit_hash,
        prev_scan_id=prev["_id"] if prev else None,
        prev_created_at=prev["scan_created_at"] if prev else None,
        is_baseline=prev is None,
        dep_count=len(deps),
        updates=diff.to_counts(),
        outdated_count=len(outdated) if outdated is not None else None,
        outdated_added=diff.outdated_added,
        outdated_resolved=diff.outdated_resolved,
    )
    return delta, outdated


async def _resolve_predecessor(db: Any, scan: _ScanRef) -> tuple[dict[str, Any] | None, dict[str, dict[str, str]]]:
    """A scan that died mid-ingest holds fewer dependencies than its delta; it is demoted and the search goes on."""
    repo = ScanUpdateDeltaRepository(db)
    for _ in range(_MAX_REPAIR_HOPS):
        prev = await repo.find_predecessor(scan.project_id, scan.branch, scan.created_at, scan.scan_id)
        if prev is None:
            return None, {}
        prev_deps = await load_scan_deps(DependencyRepository(db), prev["_id"])
        if len(prev_deps) == prev.get("dep_count"):
            return prev, prev_deps
        logger.warning(
            "Scan %s now holds %d of the %s dependencies its update delta recorded; demoting the delta",
            prev["_id"],
            len(prev_deps),
            prev.get("dep_count"),
        )
        demoted = replace(
            scan, scan_id=prev["_id"], created_at=prev["scan_created_at"], commit_hash=prev.get("commit_hash")
        )
        await _save_error_delta(db, demoted, _STALE_DEPENDENCIES_ERROR)
    return None, {}


async def _discard_delta(db: Any, scan: _ScanRef) -> None:
    """The delta would keep counting dependencies the re-ingest already deleted."""
    if not await ScanUpdateDeltaRepository(db).discard({"_id": scan.scan_id}):
        return
    logger.info("Scan %s is no longer usable; dropped its update delta", scan.scan_id)
    await _repair_successors(
        db,
        scan.project_id,
        scan.branch,
        scan.created_at,
        scan.scan_id,
        only_when_linked=True,
    )


def _diff_scans(
    prev_deps: dict[str, dict[str, str]],
    curr_deps: dict[str, dict[str, str]],
    prev_outdated: set[str] | None,
    curr_outdated: set[str] | None,
    curr_failed: set[str],
) -> _Diff:
    diff = _Diff(counts=Counter(kind for *_, kind in version_changes(prev_deps, curr_deps)))
    # Without a measurement of this scan any outdated movement would be invented.
    if curr_outdated is None:
        return diff
    if prev_outdated is None:
        # The fold sums these; dropping them would keep packages outdated across the gap out of the denominator.
        diff.outdated_added = sorted(curr_outdated)
        return diff
    diff.outdated_added = sorted(curr_outdated - prev_outdated)
    diff.outdated_resolved = sorted(resolved_outdated(prev_outdated, curr_outdated, curr_deps, curr_failed))
    return diff


async def _load_outdated(db: Any, scan_id: str) -> tuple[set[str] | None, set[str]]:
    loaded = await load_outdated_entries(AnalysisResultRepository(db), scan_id)
    if loaded is None:
        return None, set()
    entries, failed = loaded
    return {component for entry in entries if (component := entry.get("component", ""))}, failed


async def _persist(db: Any, delta: ScanUpdateDelta, outdated: set[str] | None) -> None:
    await ScanUpdateDeltaRepository(db).save(delta)
    if outdated is None:
        # A recomputation that finds no analysis must not leave the earlier set behind.
        await ScanOutdatedSetRepository(db).delete(delta.id)
        return
    await ScanOutdatedSetRepository(db).save(
        ScanOutdatedSet(
            id=delta.id,
            names=sorted(outdated),
            n=len(outdated),
            scan_created_at=delta.scan_created_at,
        )
    )


async def _save_error_delta(db: Any, scan: _ScanRef, error: str) -> None:
    """Keeps count(deltas) == count(usable scans); an outdated set must not survive next to an error document."""
    await ScanUpdateDeltaRepository(db).save(
        ScanUpdateDelta(
            id=scan.scan_id,
            project_id=scan.project_id,
            branch=scan.branch,
            scan_created_at=scan.created_at,
            commit_hash=scan.commit_hash,
            error=error[:_ERROR_MESSAGE_CAP],
        )
    )
    await ScanOutdatedSetRepository(db).delete(scan.scan_id)


async def _repair_successors(
    db: Any,
    project_id: str,
    branch: str,
    after: datetime,
    after_id: str,
    *,
    only_when_linked: bool,
) -> None:
    """Writing an anchor invalidates its successor even unlinked; a deleted anchor only affected linked ones."""
    repo = ScanUpdateDeltaRepository(db)
    anchor_id = after_id
    for _ in range(_MAX_REPAIR_HOPS):
        successor = await repo.find_successor(project_id, branch, after, after_id)
        if successor is None:
            return
        if only_when_linked and successor.get("prev_scan_id") != anchor_id:
            return
        logger.info(
            "Predecessor of scan %s changed with scan %s; recomputing its update delta",
            successor["_id"],
            anchor_id,
        )
        recomputed = await _record(db, successor["_id"])
        if recomputed is not None and recomputed.dep_count > 0:
            return
        # Neither an error document nor an SBOM-less delta is ever a predecessor, so the scan behind it is affected too.
        after = successor["scan_created_at"]
        after_id = successor["_id"]
    logger.warning(
        "Update-frequency repair stopped after %d hops from scan %s; later deltas may keep a stale predecessor",
        _MAX_REPAIR_HOPS,
        anchor_id,
    )
