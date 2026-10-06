import asyncio
import logging
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import ValidationError

from app.core.constants import WAIVER_RESTAMP_BRANCH_ACTIVE_DAYS
from app.models.project import Project
from app.models.stats import Stats
from app.models.waiver import Waiver
from app.repositories.distributed_locks import DistributedLocksRepository, new_lock_holder
from app.repositories.findings import FindingRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from app.services.analysis.stats import calculate_comprehensive_stats
from app.services.analytics.cache import get_analytics_cache
from app.services.reachability_enrichment import ComponentLanguages
from app.services.releases import released_scan_ids
from app.services.waivers.apply import restamp_waivers, waiver_fingerprint
from app.services.waivers.matching import waiver_reach_filter

logger = logging.getLogger(__name__)

# A run that outlived its job lock is waited for (at most ~6.2s) rather than dropped.
_LOCK_MAX_RETRIES = 5
_LOCK_RETRY_BASE_DELAY = 0.2
_LOCK_TTL_SECONDS = 300
# A build finalized during a pass heads next and may carry the waiver set it read before this change.
_HEAD_PASSES = 3

# The queue collection also holds the expiry sweep's watermark.
_RECALC_LOCK = "waiver_recalc"
_EXPIRY_SWEEP = "expiry_sweep"
_QUEUED = {"waiver": {"$exists": True}}


async def _restamp_scan(
    scan_id: str,
    db: AsyncIOMotorDatabase,
    waivers: list[Waiver],
    fingerprint: str,
    finding_repo: FindingRepository,
    waiver_repo: WaiverRepository | None,
) -> Stats:
    """Restamp one scan and rewrite its stats; ``waiver_repo`` also records each waiver's outcome."""
    await restamp_waivers(finding_repo, waiver_repo, scan_id, waivers)
    tally = await calculate_comprehensive_stats(db, scan_id)
    await ScanRepository(db).set_stats(
        scan_id, tally.stats, {"ignored_count": tally.ignored_count, "waiver_fingerprint": fingerprint}
    )
    return tally.stats


def _copy(waivers: list[Waiver]) -> list[Waiver]:
    return [w.model_copy(deep=True) for w in waivers]


async def _released_analysis_ids(db: AsyncIOMotorDatabase, project_id: str) -> list[str]:
    """The scans release mode reports for this project, one per environment.

    A waiver is a decision that holds now, not a property of the build it was written against, so
    revoking one has to reach the shipped build too — otherwise "what is in production" answers
    through flags frozen at analysis time and can report zero criticals against a build that has
    one. The scan's own age is disclosed rather than corrected; its waiver flags are corrected.
    """
    marked = set((await released_scan_ids(db, project_id)).values())
    if not marked:
        return []
    resolved = await ScanRepository(db).freshest_in_lineage(marked)
    return sorted({analysis.scan_id for analysis in resolved.values()})


async def _branch_tip_ids(scan_repo: ScanRepository, project: Project) -> list[str]:
    since = datetime.now(timezone.utc) - timedelta(days=WAIVER_RESTAMP_BRANCH_ACTIVE_DAYS)
    tips = await scan_repo.branch_tips(project.id, project.deleted_branches, since)
    return [tip["_id"] for _branch, _count, tip in tips if tip]


async def _acquire_with_backoff(lock_repo: DistributedLocksRepository, lock_name: str, holder_id: str) -> bool:
    for attempt in range(_LOCK_MAX_RETRIES + 1):
        if await lock_repo.acquire_lock(lock_name, holder_id, _LOCK_TTL_SECONDS):
            return True
        if attempt < _LOCK_MAX_RETRIES:
            delay = _LOCK_RETRY_BASE_DELAY * (2**attempt)
            logger.debug(
                f"Lock contention on {lock_name}; retrying in {delay:.2f}s (attempt {attempt + 1}/{_LOCK_MAX_RETRIES})."
            )
            await asyncio.sleep(delay)
    logger.warning(f"Could not acquire {lock_name} after {_LOCK_MAX_RETRIES} retries; stats may be stale")
    return False


async def recalculate_project_stats(
    project_id: str, db: AsyncIOMotorDatabase, reach: dict[str, Any] | None = None, restamp: Sequence[str] = ()
) -> Stats | None:
    """Restamp head, recent branch tips, released scans and ``restamp`` where ``reach`` can touch them, and re-cache
    head; returns head's new stats when this run restamped a settled head, else None."""
    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    waiver_repo = WaiverRepository(db)
    lock_repo = DistributedLocksRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project:
        return None

    scan_id = await scan_repo.get_latest_active_scan_id(project)
    others = {*await _released_analysis_ids(db, project_id), *await _branch_tip_ids(scan_repo, project), *restamp}
    other_ids = sorted(others - {scan_id})
    scan_ids = [*([scan_id] if scan_id else []), *other_ids]
    if not scan_ids or (reach is not None and not await finding_repo.any_in_scans(scan_ids, reach)):
        return None

    lock_name = f"stats_recalc:{project_id}"
    holder_id = new_lock_holder()
    if not await _acquire_with_backoff(lock_repo, lock_name, holder_id):
        return None

    try:
        waivers = await waiver_repo.find_active_for_project(project_id)
        fingerprint = waiver_fingerprint(waivers)
        stamped = await scan_repo.find_many_raw(
            {"_id": {"$in": scan_ids}, "waiver_fingerprint": fingerprint}, projection={"_id": 1}
        )
        current = {doc["_id"] for doc in stamped}
        # Head also records each project waiver's outcome there, which a pass on another scan does not.
        head_current = scan_id in current and all(w.last_eval_scan_id == scan_id for w in waivers if w.project_id)
        stale = [sid for sid in other_ids if sid not in current]
        logger.info(
            f"Recalculating project {project_id} with lock {lock_name}: head {scan_id} "
            f"{'current' if head_current else 'stale'}, {len(stale)} of {len(other_ids)} other scans stale"
        )
        stats = None
        head = None if head_current else scan_id
        # Each pass binds unsigned waivers to its scan in memory, so each takes its own copy.
        for _ in range(_HEAD_PASSES):
            if not head:
                break
            stats = await _restamp_scan(head, db, _copy(waivers), fingerprint, finding_repo, waiver_repo)
            synced = await scan_repo.sync_project_head(project_id)
            if synced == head:
                break
            head, stats = synced, None
        for other_id in stale:
            if not await lock_repo.renew_lock(lock_name, holder_id, _LOCK_TTL_SECONDS):
                logger.warning(f"Lost lock {lock_name} partway; the recalculation holding it now stamps the rest")
                break
            await _restamp_scan(other_id, db, _copy(waivers), fingerprint, finding_repo, None)
        return stats

    finally:
        await lock_repo.release_lock(lock_name, holder_id)
        logger.debug(f"Released lock {lock_name} for project {project_id}")


async def restamp_single_scan(db: AsyncIOMotorDatabase, project_id: str, scan_id: str) -> None:
    """Restamp one scan with the project's active waivers under its stats lock, ahead of the queued recalculation."""
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"stats_recalc:{project_id}"
    holder_id = new_lock_holder()
    if not await _acquire_with_backoff(lock_repo, lock_name, holder_id):
        return
    try:
        waivers = await WaiverRepository(db).find_active_for_project(project_id)
        await _restamp_scan(scan_id, db, waivers, waiver_fingerprint(waivers), FindingRepository(db), None)
    finally:
        await lock_repo.release_lock(lock_name, holder_id)


async def refresh_scan_stats(
    db: AsyncIOMotorDatabase, project_id: str, scan_id: str, component_languages: ComponentLanguages | None = None
) -> None:
    """Recompute one scan's stats under the project's stats lock and re-cache the project's head."""
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"stats_recalc:{project_id}"
    holder_id = new_lock_holder()
    if not await _acquire_with_backoff(lock_repo, lock_name, holder_id):
        return
    try:
        scan_repo = ScanRepository(db)
        tally = await calculate_comprehensive_stats(db, scan_id, component_languages)
        # Stamped so a retention batch that bundled the stats before this write keeps the scan.
        await scan_repo.set_stats(scan_id, tally.stats, {"updated_at": datetime.now(timezone.utc)})
        await scan_repo.sync_project_head(project_id)
    finally:
        await lock_repo.release_lock(lock_name, holder_id)


async def request_waiver_recalc(db: AsyncIOMotorDatabase, waiver: Waiver, restamp: Sequence[str] = ()) -> None:
    """Queue a created, changed or deleted waiver for run_waiver_recalc, with the scans ``restamp`` names."""
    await db.waiver_recalc.insert_one({"waiver": waiver.model_dump(by_alias=True), "restamp": list(restamp)})


async def run_waiver_recalc(db: AsyncIOMotorDatabase) -> None:
    """Recalculate what queued waiver changes and new expiries reach; a change stays queued until its pass is done."""
    lock_repo = DistributedLocksRepository(db)
    holder_id = new_lock_holder()
    while await lock_repo.acquire_lock(_RECALC_LOCK, holder_id, _LOCK_TTL_SECONDS):
        try:
            await _queue_expired_waivers(db)
            while queued := await db.waiver_recalc.find(_QUEUED).to_list(None):
                if not await _recalculate_changed(db, queued, lock_repo, holder_id):
                    return
                await db.waiver_recalc.delete_many({"_id": {"$in": [doc["_id"] for doc in queued]}})
                # Reads during the pass may have cached the flags it replaced.
                get_analytics_cache().clear()
        finally:
            await lock_repo.release_lock(_RECALC_LOCK, holder_id)
        # A change queued as this run finished found the lock still taken and was left to it.
        if await db.waiver_recalc.find_one(_QUEUED, {"_id": 1}) is None:
            return


async def _queue_expired_waivers(db: AsyncIOMotorDatabase) -> None:
    """Queue the waivers that expired since the last sweep: an expiry changes the active set as a delete does."""
    now = datetime.now(timezone.utc)
    sweep = await db.waiver_recalc.find_one({"_id": _EXPIRY_SWEEP})
    window: dict[str, Any] = {"$lte": now}
    if sweep:
        window["$gt"] = sweep["swept_until"]
    if expired := await db.waivers.find({"expiration_date": window}).to_list(None):
        await db.waiver_recalc.insert_many([{"waiver": doc} for doc in expired])
    await db.waiver_recalc.update_one({"_id": _EXPIRY_SWEEP}, {"$set": {"swept_until": now}}, upsert=True)


async def _recalculate_changed(
    db: AsyncIOMotorDatabase, queued: list[dict[str, Any]], lock_repo: DistributedLocksRepository, holder_id: str
) -> bool:
    """Recalculate every project the queued waivers can reach, each on its own; False once the run lost its lock."""
    changed = []
    restamps: dict[str, list[str]] = {}
    for doc in queued:
        try:
            waiver = Waiver(**doc["waiver"])
        except ValidationError:
            logger.warning("Dropping queued waiver change %s: its waiver does not load", doc["_id"])
            continue
        changed.append(waiver)
        if waiver.project_id:
            restamps.setdefault(waiver.project_id, []).extend(doc.get("restamp", []))
    reaches = [r for w in changed if not w.project_id and (r := waiver_reach_filter(w)) is not None]
    targets: dict[str, dict[str, Any] | None] = {}
    if reaches:
        reach = reaches[0] if len(reaches) == 1 else {"$or": reaches}
        # Read up front: a cursor held open across the whole run times out on the server partway.
        targets = {project["_id"]: reach async for project in db.projects.find({}, {"_id": 1})}
    # A project waiver changes its project's active set, whatever the project's findings hold.
    targets |= {w.project_id: None for w in changed if w.project_id}
    failed = 0
    for project_id, project_reach in targets.items():
        if not await lock_repo.renew_lock(_RECALC_LOCK, holder_id, _LOCK_TTL_SECONDS):
            logger.warning("Waiver recalculation lost its lock; the run holding it now resumes the queued changes")
            return False
        try:
            await recalculate_project_stats(project_id, db, project_reach, restamp=restamps.get(project_id, ()))
        except Exception:
            failed += 1
            logger.exception("Waiver recalculation failed for project %s", project_id)
    logger.info("Waiver recalculation: %d changes, %d projects, %d failed", len(changed), len(targets), failed)
    return True
