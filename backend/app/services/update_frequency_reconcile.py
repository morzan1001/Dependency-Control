"""Reconcile the update-frequency delta ledger against the scans it summarises.

The ledger is a derivation, and the writer is not on every path that touches a scan: an
insert or a status change leaves a hole, and a delete takes the movement across the
deleted scan out of the window sum, while the analytics tab keeps serving numbers as if
nothing happened. This turns that silence into a metric and repairs what it finds.

A delete is visible only through the successor still pointing at the deleted scan, so
one at the newest end of a branch leaves the two censuses agreeing and is not seen here.
"""

import asyncio
import logging
import os
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import settings
from app.core.metrics import update_frequency_reconcile_drift_total
from app.models.update_frequency import UPDATE_DELTA_SCHEMA_VERSION
from app.repositories.distributed_locks import DistributedLocksRepository
from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    LedgerEntry,
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
    window_scan_ids_by_branch,
)
from app.services.update_frequency import as_utc
from app.services.update_frequency_rollup import record_scan_update_delta

logger = logging.getLogger(__name__)

_LOCK_NAME = "update_frequency_reconcile"
# Longer than any capped run can last, short enough that a pod killed mid-run does not
# hold the next night's slot.
_LOCK_TTL_SECONDS = 1800

# The comparison endpoint's default window. A caller may ask for a wider one; history
# older than this is the backfill script's job, not a nightly sweep's.
_RECONCILE_WINDOW_DAYS = 90

# Recomputing a delta re-reads two dependency sets (~1.6 MB), so the cap is what keeps
# this from becoming a backfill: 500 at the pause below is ~70 s of work.
_MAX_REPAIRS = 500
_REPAIR_PAUSE_SECONDS = 0.1
# Deleting is a single bulk operation per chain, so this only bounds how much of a mass
# scan deletion one run cleans up.
_MAX_ORPHAN_DELETES = 5000


@dataclass(frozen=True)
class _Repair:
    scan_id: str
    scan_created_at: datetime
    kind: str


@dataclass(frozen=True)
class _ChainDrift:
    repairs: tuple[_Repair, ...]
    orphans: tuple[str, ...]
    owed: frozenset[str]

    def __bool__(self) -> bool:
        return bool(self.repairs or self.orphans)


@dataclass
class ReconcileReport:
    chains: int = 0
    drifted_chains: int = 0
    resolved: Counter = field(default_factory=Counter)
    deferred: Counter = field(default_factory=Counter)

    def totals(self) -> tuple[int, int]:
        return sum(self.resolved.values()), sum(self.deferred.values())

    def repairs_spent(self) -> int:
        """Deltas derived again this run; orphans are a bulk delete and cost nothing like it."""
        return sum(count for kind, count in self.resolved.items() if kind != "orphan")


async def run_update_frequency_reconcile(db: Any) -> ReconcileReport | None:
    """Reconcile the ledger once, or return None when this pod is not the one doing it.

    The housekeeping loop runs in every pod and takes no lock of its own, so without one
    here fifteen pods would re-derive the same deltas at once and collide with the
    writer's own successor repair.
    """
    if not settings.UPDATE_FREQUENCY_ROLLUP_ENABLED:
        return None

    locks = DistributedLocksRepository(db)
    holder_id = f"update-frequency-reconcile-{os.getenv('HOSTNAME', 'unknown')}"
    if not await locks.acquire_lock(_LOCK_NAME, holder_id, ttl_seconds=_LOCK_TTL_SECONDS):
        logger.debug("Update-frequency reconcile skipped: another pod holds the lock")
        return None
    try:
        return await _reconcile(db)
    finally:
        await locks.release_lock(_LOCK_NAME, holder_id)


async def _reconcile(db: Any) -> ReconcileReport:
    since = datetime.now(tz=timezone.utc) - timedelta(days=_RECONCILE_WINDOW_DAYS)
    project_ids = sorted(str(project_id) for project_id in await db.projects.distinct("_id"))
    # The ledger is read first so that a scan finishing between the two censuses reads as
    # missing, which re-derives idempotently. Reading scans first would make the same scan
    # look like a delta nobody owns, and the repair for that is a delete.
    ledger = await ScanUpdateDeltaRepository(db).window_ledger_by_branch(project_ids, since)
    scans = await window_scan_ids_by_branch(ScanRepository(db), project_ids, since)

    chains = sorted(set(scans) | set(ledger))
    report = ReconcileReport(chains=len(chains))
    for chain in chains:
        drift = _classify(scans.get(chain, ()), ledger.get(chain, {}), since)
        if not drift:
            continue
        report.drifted_chains += 1
        await _repair_chain(db, chain, drift, report)

    _publish(report)
    return report


def _classify(scans: Sequence[tuple[str, datetime]], ledger: dict[str, LedgerEntry], since: datetime) -> _ChainDrift:
    """What one chain's ledger holds too little, too old, too detached, or too much of."""
    owed = frozenset(scan_id for scan_id, _created_at in scans)
    repairs = []
    for scan_id, created_at in scans:
        entry = ledger.get(scan_id)
        if entry is None:
            repairs.append(_Repair(scan_id, created_at, "missing"))
        elif entry.schema_version != UPDATE_DELTA_SCHEMA_VERSION:
            repairs.append(_Repair(scan_id, created_at, "stale"))
        elif _severed(entry, owed, ledger, since):
            repairs.append(_Repair(scan_id, created_at, "severed"))
    # A delta whose scan lost its usable status counts here too: the writer drops such a
    # delta as well, because it keeps describing dependencies a re-ingest already deleted.
    orphans = tuple(sorted(delta_id for delta_id in ledger if delta_id not in owed))
    return _ChainDrift(tuple(repairs), orphans, owed)


def _severed(entry: LedgerEntry, owed: frozenset[str], ledger: dict[str, LedgerEntry], since: datetime) -> bool:
    """Whether the delta was diffed against a scan that went away together with its delta.

    Retention deletes both at once, which leaves nothing else out of step: the successor's
    own numbers still describe a comparison the window no longer contains. A predecessor
    from before the window is out of scope, and one whose delta is still here is an orphan
    this run deletes and repairs as one.
    """
    prev = entry.prev_scan_id
    if prev is None or prev in owed or prev in ledger:
        return False
    return entry.prev_created_at is not None and entry.prev_created_at >= since


async def _repair_chain(db: Any, chain: tuple[str, str], drift: _ChainDrift, report: ReconcileReport) -> None:
    deleted = await _delete_orphans(db, chain, drift.orphans, report)
    repairs = {repair.scan_id: repair for repair in drift.repairs}
    for dependent in await _dependents_of(db, chain, deleted, drift.owed):
        repairs.setdefault(dependent.scan_id, dependent)

    # Oldest first: a newer scan derived before its predecessor finds no predecessor
    # delta, is stored as a baseline, and has to be written a second time by the
    # writer's own repair once the older one arrives.
    for repair in sorted(repairs.values(), key=lambda item: (item.scan_created_at, item.scan_id)):
        if report.repairs_spent() >= _MAX_REPAIRS:
            report.deferred[repair.kind] += 1
            continue
        await record_scan_update_delta(db, repair.scan_id)
        report.resolved[repair.kind] += 1
        # Same courtesy rate the backfill runs at; the scans this competes with are live.
        await asyncio.sleep(_REPAIR_PAUSE_SECONDS)


async def _delete_orphans(
    db: Any, chain: tuple[str, str], orphans: tuple[str, ...], report: ReconcileReport
) -> set[str]:
    if not orphans:
        return set()
    room = max(_MAX_ORPHAN_DELETES - report.resolved["orphan"], 0)
    doomed = list(orphans[:room])
    if len(doomed) < len(orphans):
        report.deferred["orphan"] += len(orphans) - len(doomed)
    if not doomed:
        return set()
    project_id, branch = chain
    # Scoped to the chain that diagnosed them: the same scan id can sit in another chain
    # whose delta a later pass already re-derived correctly.
    await ScanUpdateDeltaRepository(db).delete_many(
        {"_id": {"$in": doomed}, "project_id": project_id, "branch": branch}
    )
    await ScanOutdatedSetRepository(db).delete_many({"_id": {"$in": doomed}})
    report.resolved["orphan"] += len(doomed)
    return set(doomed)


async def _dependents_of(db: Any, chain: tuple[str, str], deleted: set[str], owed: frozenset[str]) -> list[_Repair]:
    """Deltas that were diffed against a scan just removed from the ledger.

    Their counts describe a comparison against dependencies nobody can read any more, so
    the movement across the removed scan is lost until they are derived again. One whose
    own scan is gone is an orphan the delete cap deferred: the writer would find no scan
    to derive from, so handing it over would count a repair that never happened.
    """
    project_id, branch = chain
    docs = await ScanUpdateDeltaRepository(db).find_dependents(project_id, branch, sorted(deleted))
    return [_Repair(doc["_id"], as_utc(doc["scan_created_at"]), "dependent") for doc in docs if doc["_id"] in owed]


def _publish(report: ReconcileReport) -> None:
    # Every kind the run tallied is exported, so the metric cannot report less drift than
    # the warning below names.
    for outcome, tally in (("resolved", report.resolved), ("deferred", report.deferred)):
        for kind, count in tally.items():
            if count:
                update_frequency_reconcile_drift_total.labels(kind=kind, outcome=outcome).inc(count)

    resolved, deferred = report.totals()
    if not resolved and not deferred:
        logger.info("Update-frequency reconcile: %d chain(s) in step with the ledger", report.chains)
        return
    logger.warning(
        "Update-frequency reconcile found drift in %d of %d chain(s): "
        "derived %d missing, %d outdated, %d severed and %d successor delta(s), deleted %d orphan(s)",
        report.drifted_chains,
        report.chains,
        report.resolved["missing"],
        report.resolved["stale"],
        report.resolved["severed"],
        report.resolved["dependent"],
        report.resolved["orphan"],
    )
    if deferred:
        logger.warning(
            "Update-frequency reconcile hit its per-run caps (%d repairs, %d orphan deletes) and left "
            "%d missing, %d outdated, %d severed, %d successor and %d orphan delta(s) for the next run",
            _MAX_REPAIRS,
            _MAX_ORPHAN_DELETES,
            report.deferred["missing"],
            report.deferred["stale"],
            report.deferred["severed"],
            report.deferred["dependent"],
            report.deferred["orphan"],
        )
