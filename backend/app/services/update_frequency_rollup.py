"""Per-scan update-frequency rollup: one delta document per usable scan.

Both dependency sets of a comparison are read straight from ``dependencies``,
so a recomputation always reproduces the same document.
"""

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.config import settings
from app.core.constants import SCAN_USABLE_STATUSES
from app.core.metrics import update_frequency_delta_writes_total
from app.models.update_frequency import ScanOutdatedSet, ScanUpdateDelta, UpdateCounts, UpdateSample
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.update_frequency import ScanOutdatedSetRepository, ScanUpdateDeltaRepository
from app.services.update_frequency import (
    DEP_PROJECTION,
    as_utc,
    classify_version_change,
    fold_scan_deps,
    load_outdated_entries,
)

logger = logging.getLogger(__name__)

_SCAN_PROJECTION = {
    "project_id": 1,
    "branch": 1,
    "created_at": 1,
    "commit_hash": 1,
    "status": 1,
    "is_rescan": 1,
}
# An outdated_packages document averages 48 KB; only the component names are needed.
_OUTDATED_PROJECTION = {"result.outdated_dependencies.component": 1}

_UPDATES_SAMPLE_CAP = 20
_SAMPLE_RANK = {"major": 0, "minor": 1, "patch": 2, "unknown": 3, "downgrade": 4}
_ERROR_MESSAGE_CAP = 300
_STALE_DEPENDENCIES_ERROR = "StaleDelta: the scan's dependencies changed after this delta was written"
# Bounds the self-healing walks along a branch timeline.
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
    samples: list[UpdateSample] = field(default_factory=list)
    outdated_added: list[str] = field(default_factory=list)
    outdated_resolved: list[str] = field(default_factory=list)

    def to_counts(self) -> UpdateCounts:
        return UpdateCounts(
            patch=self.counts["patch"],
            minor=self.counts["minor"],
            major=self.counts["major"],
            unknown=self.counts["unknown"],
            downgrade=self.counts["downgrade"],
        )

    def total_updates(self) -> int:
        return sum(count for kind, count in self.counts.items() if kind != "downgrade")


async def record_scan_update_delta(db: Any, scan_id: str) -> None:
    """Record the dependency movement of one scan against its branch predecessor.

    Never raises: a rollup for the analytics tab must not fail the ingest or the
    restore that triggered it, both of which treat an exception as a lost scan.
    """
    try:
        if not settings.UPDATE_FREQUENCY_ROLLUP_ENABLED:
            return
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
        logger.exception("Update-frequency rollup aborted for scan %s", scan_id)
        update_frequency_delta_writes_total.labels(result="error").inc()


async def _record(db: Any, scan_id: str) -> ScanUpdateDelta | None:
    """The delta of ``scan_id``, or None when the scan is skipped or its computation failed."""
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
        await _record_failure(db, scan, exc)
        return None

    update_frequency_delta_writes_total.labels(result="ok").inc()
    return delta


async def _load_scan(db: Any, scan_id: str) -> _ScanRef | None:
    doc = await db.scans.find_one({"_id": scan_id}, _SCAN_PROJECTION)
    if doc is None:
        return None
    created_at = doc.get("created_at")
    if not isinstance(created_at, datetime):
        logger.warning("Scan %s has no usable created_at; skipping its update delta", scan_id)
        return None
    return _ScanRef(
        scan_id=scan_id,
        project_id=doc.get("project_id", ""),
        branch=doc.get("branch", ""),
        created_at=as_utc(created_at),
        commit_hash=doc.get("commit_hash"),
        usable=doc.get("status") in SCAN_USABLE_STATUSES and not doc.get("is_rescan"),
    )


async def _compute_delta(db: Any, scan: _ScanRef) -> tuple[ScanUpdateDelta, set[str] | None]:
    deps = await _load_deps(db, scan.scan_id)
    outdated = await _load_outdated(db, scan.scan_id)

    prev, prev_deps = await _resolve_predecessor(db, scan)
    if prev is None:
        diff = _Diff()
    else:
        prev_outdated = await _load_outdated(db, prev["_id"])
        diff = _diff_scans(prev_deps, deps, prev_outdated, outdated)

    delta = ScanUpdateDelta(
        id=scan.scan_id,
        project_id=scan.project_id,
        branch=scan.branch,
        scan_created_at=scan.created_at,
        commit_hash=scan.commit_hash,
        prev_scan_id=prev["_id"] if prev else None,
        prev_created_at=as_utc(prev["scan_created_at"]) if prev else None,
        is_baseline=prev is None,
        dep_count=len(deps),
        updates=diff.to_counts(),
        total_updates=diff.total_updates(),
        outdated_count=len(outdated) if outdated is not None else None,
        outdated_added=diff.outdated_added,
        outdated_resolved=diff.outdated_resolved,
        eco=_eco_counts(deps),
        updates_sample=diff.samples,
    )
    return delta, outdated


async def _resolve_predecessor(db: Any, scan: _ScanRef) -> tuple[dict[str, Any] | None, dict[str, dict[str, str]]]:
    """The newest branch predecessor whose dependencies still match its delta, and those dependencies.

    An ingest deletes a scan's dependencies before rewriting them, so a scan that
    dies in between holds fewer of them than its delta recorded. Diffing against
    that leftover reports the missing packages as absent rather than unchanged,
    so it is demoted to an error document and the search continues further back.
    """
    repo = ScanUpdateDeltaRepository(db)
    for _ in range(_MAX_REPAIR_HOPS):
        prev = await repo.find_predecessor(scan.project_id, scan.branch, scan.created_at, scan.scan_id)
        if prev is None:
            return None, {}
        prev_deps = await _load_deps(db, prev["_id"])
        if len(prev_deps) == prev.get("dep_count"):
            return prev, prev_deps
        logger.warning(
            "Scan %s now holds %d of the %s dependencies its update delta recorded; demoting the delta",
            prev["_id"],
            len(prev_deps),
            prev.get("dep_count"),
        )
        await repo.save(
            ScanUpdateDelta(
                id=prev["_id"],
                project_id=scan.project_id,
                branch=scan.branch,
                scan_created_at=as_utc(prev["scan_created_at"]),
                error=_STALE_DEPENDENCIES_ERROR,
            )
        )
        await ScanOutdatedSetRepository(db).delete(prev["_id"])
    return None, {}


async def _discard_delta(db: Any, scan: _ScanRef) -> None:
    """Drop the delta of a scan that lost its usable status, e.g. a failed re-ingest.

    The delta would keep counting dependencies the re-ingest already deleted, so
    the successors that compared against it are recomputed against an older scan.
    """
    if not await ScanUpdateDeltaRepository(db).delete(scan.scan_id):
        return
    await ScanOutdatedSetRepository(db).delete(scan.scan_id)
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
) -> _Diff:
    counts: Counter = Counter()
    samples: list[UpdateSample] = []

    for identity, curr in curr_deps.items():
        prev = prev_deps.get(identity)
        if prev is None or prev["version"] == curr["version"]:
            continue
        kind = classify_version_change(prev["version"], curr["version"])
        if kind == "none":  # same PEP 440 identity, e.g. v1.0.0 vs 1.0.0
            continue
        counts[kind] += 1
        samples.append(
            UpdateSample(
                n=curr["display"],
                t=curr["type"],
                p=curr["purl"] or None,
                ov=prev["version"],
                nv=curr["version"],
                k=kind,
                wo=prev_outdated is not None and prev["name"] in prev_outdated,
            )
        )

    # Mongo document order is unstable, so the cap needs a total order of its own.
    samples.sort(key=lambda sample: (_SAMPLE_RANK[sample.k], sample.n, sample.nv))
    diff = _Diff(counts=counts, samples=samples[:_UPDATES_SAMPLE_CAP])
    # Without a measurement of this scan any outdated movement would be invented.
    if curr_outdated is None:
        return diff
    if prev_outdated is None:
        # Nothing to subtract, so every outdated package here is newly observed.
        # The fold sums these lists, and dropping them would leave packages that
        # went outdated across the unmeasured scan out of the coverage denominator.
        diff.outdated_added = sorted(curr_outdated)
        return diff
    curr_names = {info["name"] for info in curr_deps.values()}
    diff.outdated_added = sorted(curr_outdated - prev_outdated)
    # A package that vanished was not brought up to date.
    diff.outdated_resolved = sorted((prev_outdated & curr_names) - curr_outdated)
    return diff


def _eco_counts(deps: dict[str, dict[str, str]]) -> dict[str, int]:
    return dict(Counter(info["type"] for info in deps.values()))


async def _load_deps(db: Any, scan_id: str) -> dict[str, dict[str, str]]:
    docs = await DependencyRepository(db).find_all({"scan_id": scan_id}, projection=DEP_PROJECTION)
    return fold_scan_deps(docs)


async def _load_outdated(db: Any, scan_id: str) -> set[str] | None:
    """Component names the scan flagged outdated, or None when it carries no such analysis."""
    entries = await load_outdated_entries(AnalysisResultRepository(db), scan_id, _OUTDATED_PROJECTION)
    if entries is None:
        return None
    return {component for entry in entries if (component := entry.get("component", ""))}


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


async def _record_failure(db: Any, scan: _ScanRef, exc: Exception) -> None:
    """Keep count(deltas) == count(usable scans) even when the computation failed.

    An outdated set only ever accompanies a delta that was computed, so an
    earlier one must not survive next to the error document.
    """
    await ScanUpdateDeltaRepository(db).save(
        ScanUpdateDelta(
            id=scan.scan_id,
            project_id=scan.project_id,
            branch=scan.branch,
            scan_created_at=scan.created_at,
            commit_hash=scan.commit_hash,
            error=f"{type(exc).__name__}: {exc}"[:_ERROR_MESSAGE_CAP],
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
    """Recompute later deltas of the branch whose predecessor changed under them.

    A delta describes a diff against the dependencies the anchor held when it was
    written, so writing the anchor invalidates its successor whatever the successor
    records as its predecessor. ``only_when_linked`` narrows that to successors
    pointing at the anchor, which is all a *deleted* anchor can have affected.

    SBOM-less scans keep the walk going: they cannot be a predecessor, so the
    next scan that carries dependencies is affected as well.
    """
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
        # A failed recomputation leaves an error document, which is never a
        # predecessor either, so the scan behind it is affected as well.
        after = as_utc(successor["scan_created_at"])
        after_id = successor["_id"]
    logger.warning(
        "Update-frequency repair stopped after %d hops from scan %s; later deltas may keep a stale predecessor",
        _MAX_REPAIR_HOPS,
        anchor_id,
    )
