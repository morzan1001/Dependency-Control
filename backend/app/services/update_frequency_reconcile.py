"""The writer is not on every scan path; a delete shows only via its successor, so one at a branch tip stays unseen."""

import asyncio
import logging
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from typing import Any

from app.core.config import settings
from app.core.metrics import update_frequency_reconcile_drift_total
from app.models.update_frequency import UPDATE_DELTA_SCHEMA_VERSION
from app.repositories.distributed_locks import DistributedLocksRepository, new_lock_holder
from app.repositories.scans import ScanRepository
from app.repositories.update_frequency import (
    LedgerEntry,
    ScanOutdatedSetRepository,
    ScanUpdateDeltaRepository,
    window_scan_ids_by_branch,
)
from app.services.update_frequency_rollup import record_scan_update_delta

logger = logging.getLogger(__name__)

_LOCK_NAME = "update_frequency_reconcile"
# Held to expiry, never released: it outlasts the quiet hour in which every pod checks once.
_LOCK_TTL_SECONDS = 2 * 3600

# The comparison endpoint's default window; the sweep repairs nothing older, even if a caller asks wider.
_RECONCILE_WINDOW_DAYS = 90

# A repair re-reads two dependency sets (~1.6 MB); the cap keeps this from becoming a backfill (~70 s).
_MAX_REPAIRS = 500
_REPAIR_PAUSE_SECONDS = 0.1
# Deletes are one bulk operation per chain; this bounds how much of a mass deletion one run cleans up.
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
        """Orphans are excluded: a bulk delete costs nothing like a re-derivation."""
        return sum(count for kind, count in self.resolved.items() if kind != "orphan")


async def run_update_frequency_reconcile(db: Any) -> ReconcileReport | None:
    """Locked: the housekeeping loop runs in every pod, which would otherwise all re-derive the same deltas."""
    if not settings.UPDATE_FREQUENCY_ROLLUP_ENABLED:
        return None

    if not await DistributedLocksRepository(db).acquire_lock(
        _LOCK_NAME, new_lock_holder(), ttl_seconds=_LOCK_TTL_SECONDS
    ):
        logger.debug("Update-frequency reconcile skipped: another pod holds the lock")
        return None
    return await _reconcile(db)


async def _reconcile(db: Any) -> ReconcileReport:
    since = datetime.now(tz=timezone.utc) - timedelta(days=_RECONCILE_WINDOW_DAYS)
    project_ids = sorted(str(project_id) for project_id in await db.projects.distinct("_id"))
    # Ledger first: a scan finishing between the reads then looks missing (idempotent), not like an orphan to delete.
    ledger = await ScanUpdateDeltaRepository(db).window_ledger_by_branch(project_ids, since)
    scans = await window_scan_ids_by_branch(ScanRepository(db), project_ids, since)

    chains = sorted(set(scans) | set(ledger))
    report = ReconcileReport(chains=len(chains))
    for chain in chains:
        drift = _classify(scans.get(chain, ()), ledger.get(chain, {}), since)
        if not drift:
            continue
        report.drifted_chains += 1
        await _repair_chain(db, chain, drift, report, since)

    _publish(report)
    return report


def _classify(scans: Sequence[tuple[str, datetime]], ledger: dict[str, LedgerEntry], since: datetime) -> _ChainDrift:
    owed = frozenset(scan_id for scan_id, _created_at in scans)
    skipping = _skip_links(ledger, owed)
    repairs = []
    for scan_id, created_at in scans:
        entry = ledger.get(scan_id)
        if entry is None:
            repairs.append(_Repair(scan_id, created_at, "missing"))
        elif entry.schema_version != UPDATE_DELTA_SCHEMA_VERSION:
            repairs.append(_Repair(scan_id, created_at, "stale"))
        elif _severed(entry, owed, ledger, since):
            repairs.append(_Repair(scan_id, created_at, "severed"))
        elif scan_id in skipping:
            repairs.append(_Repair(scan_id, created_at, "relink"))
    # A delta whose scan lost its usable status is an orphan too, as it describes deleted dependencies.
    orphans = tuple(sorted(delta_id for delta_id in ledger if delta_id not in owed))
    return _ChainDrift(tuple(repairs), orphans, owed)


def _severed(entry: LedgerEntry, owed: frozenset[str], ledger: dict[str, LedgerEntry], since: datetime) -> bool:
    """Retention deletes a scan with its delta, leaving the successor describing a comparison the window lacks."""
    prev = entry.prev_scan_id
    if prev is None or prev in owed or prev in ledger:
        return False
    return entry.prev_created_at is not None and entry.prev_created_at >= since


def _skip_links(ledger: dict[str, LedgerEntry], owed: frozenset[str]) -> set[str]:
    """Deltas diffed against a scan other than the comparable one before them, as racing ingests leave."""
    chain = sorted(
        (entry.scan_created_at, scan_id) for scan_id, entry in ledger.items() if scan_id in owed and entry.comparable
    )
    # The oldest delta's predecessor may predate the window; an orphan's dependent is repaired once it is deleted.
    return {
        scan_id
        for (_, before), (_, scan_id) in pairwise(chain)
        if (prev := ledger[scan_id].prev_scan_id) != before and (prev in owed or prev not in ledger)
    }


async def _repair_chain(
    db: Any, chain: tuple[str, str], drift: _ChainDrift, report: ReconcileReport, since: datetime
) -> None:
    deleted = await _delete_orphans(db, chain, drift.orphans, report)
    repairs = {repair.scan_id: repair for repair in drift.repairs}
    for dependent in await _dependents_of(db, chain, deleted, drift.owed, since):
        repairs.setdefault(dependent.scan_id, dependent)

    # Oldest first: a newer scan derived before its predecessor would be stored as a baseline and written twice.
    for repair in sorted(repairs.values(), key=lambda item: (item.scan_created_at, item.scan_id)):
        if report.repairs_spent() >= _MAX_REPAIRS:
            report.deferred[repair.kind] += 1
            continue
        await record_scan_update_delta(db, repair.scan_id)
        report.resolved[repair.kind] += 1
        # The scans this competes with are live.
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
    # Scoped to the diagnosing chain: the scan id can sit in another chain already re-derived correctly.
    await ScanUpdateDeltaRepository(db).delete_many(
        {"_id": {"$in": doomed}, "project_id": project_id, "branch": branch}
    )
    await ScanOutdatedSetRepository(db).delete_many({"_id": {"$in": doomed}})
    report.resolved["orphan"] += len(doomed)
    return set(doomed)


async def _dependents_of(
    db: Any, chain: tuple[str, str], deleted: set[str], owed: frozenset[str], since: datetime
) -> list[_Repair]:
    """One whose own scan is gone is a deferred orphan; handing it over would count a repair that never happened."""
    project_id, branch = chain
    # A dependent is newer than the in-window orphan it names, so the window bounds the index scan.
    docs = await ScanUpdateDeltaRepository(db).find_dependents(project_id, branch, sorted(deleted), since)
    return [_Repair(doc["_id"], doc["scan_created_at"], "dependent") for doc in docs if doc["_id"] in owed]


def _publish(report: ReconcileReport) -> None:
    # Every tallied kind is exported so the metric never reports less drift than the warning below.
    for outcome, tally in (("resolved", report.resolved), ("deferred", report.deferred)):
        for kind, count in tally.items():
            if count:
                update_frequency_reconcile_drift_total.labels(kind=kind, outcome=outcome).inc(count)

    resolved, deferred = report.totals()
    if not resolved and not deferred:
        logger.info("Update-frequency reconcile: %d chain(s) in step with the ledger", report.chains)
        return
    logger.warning(
        "Update-frequency reconcile found drift in %d of %d chain(s): derived %d missing, %d outdated, "
        "%d severed, %d relinked and %d successor delta(s), deleted %d orphan(s)",
        report.drifted_chains,
        report.chains,
        report.resolved["missing"],
        report.resolved["stale"],
        report.resolved["severed"],
        report.resolved["relink"],
        report.resolved["dependent"],
        report.resolved["orphan"],
    )
    if deferred:
        logger.warning(
            "Update-frequency reconcile hit its per-run caps (%d repairs, %d orphan deletes) and left "
            "%d missing, %d outdated, %d severed, %d relink, %d successor and %d orphan delta(s) for the next run",
            _MAX_REPAIRS,
            _MAX_ORPHAN_DELETES,
            report.deferred["missing"],
            report.deferred["stale"],
            report.deferred["severed"],
            report.deferred["relink"],
            report.deferred["dependent"],
            report.deferred["orphan"],
        )
