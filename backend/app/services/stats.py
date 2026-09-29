import asyncio
import logging
import os
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Project
from app.models.stats import Stats
from app.models.waiver import Waiver
from app.repositories import (
    DistributedLocksRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
    WaiverRepository,
)
from app.services.analysis.stats import calculate_comprehensive_stats
from app.services.releases import released_scan_ids
from app.services.waivers.apply import restamp_waivers, waiver_fingerprint
from app.services.waivers.matching import waiver_reach_filter

logger = logging.getLogger(__name__)

# Lock-acquisition retry policy for recalculate_project_stats. Recalc is triggered
# fire-and-forget from waiver CRUD endpoints, so a dropped run (None return) leaves
# stats stale until an unrelated event re-triggers it. Bounded exponential backoff
# lets a contending run wait for the current holder to finish and then recompute
# against the fully-committed waiver set. Total worst-case wait ~= 0.2*(2^5-1) = 6.2s.
_LOCK_MAX_RETRIES = 5
_LOCK_RETRY_BASE_DELAY = 0.2


async def _restamp_scan(
    scan_id: str,
    db: AsyncIOMotorDatabase,
    waivers: list[Waiver],
    fingerprint: str,
    finding_repo: FindingRepository,
    waiver_repo: WaiverRepository | None,
) -> Stats:
    """Re-apply the current waiver set to one scan and rewrite its stats from the result; ``waiver_repo``,
    when given, records what each waiver matched there."""
    await restamp_waivers(finding_repo, waiver_repo, scan_id, waivers)
    tally = await calculate_comprehensive_stats(db, scan_id)
    await ScanRepository(db).update_raw(
        scan_id,
        {
            "$set": {
                "stats": tally.stats.model_dump(),
                "ignored_count": tally.ignored_count,
                "waiver_fingerprint": fingerprint,
            }
        },
    )
    return tally.stats


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
    tips = await scan_repo.branch_tips(project.id, project.deleted_branches)
    return [tip["_id"] for _branch, _count, tip in tips if tip]


async def recalculate_project_stats(
    project_id: str, db: AsyncIOMotorDatabase, reach: dict[str, Any] | None = None
) -> Stats | None:
    """Re-stamp the project's active waiver set onto its head, every branch tip and the scans release
    mode reports, and carry head's stats onto the project.

    Restamps under a distributed lock to prevent races when pods modify waivers concurrently; a scan
    already stamped with this waiver set is left alone. ``reach`` is a finding filter: a project none
    of whose scans holds a match is not recalculated. Returns head's new stats, None if head needed none.
    """
    project_repo = ProjectRepository(db)
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    waiver_repo = WaiverRepository(db)
    lock_repo = DistributedLocksRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project:
        return None

    scan_id = await scan_repo.get_latest_active_scan_id(project)
    others = {*await _released_analysis_ids(db, project_id), *await _branch_tip_ids(scan_repo, project)}
    other_ids = sorted(others - {scan_id})
    scan_ids = [*([scan_id] if scan_id else []), *other_ids]
    if not scan_ids or (reach is not None and not await finding_repo.any_in_scans(scan_ids, reach)):
        return None

    # Acquire distributed lock to prevent race conditions
    lock_name = f"stats_recalc:{project_id}"
    holder_id = f"pod-{os.getenv('HOSTNAME', 'unknown')}-{os.getpid()}"

    # Retry with bounded exponential backoff instead of dropping the recalc on the
    # first contention. Two concurrent waiver changes must both end up reflected: the
    # loser of the lock waits for the holder to release, then recomputes against the
    # now-committed waiver set (avoids stale stats / stale ignored_count).
    lock_acquired = False
    for attempt in range(_LOCK_MAX_RETRIES + 1):
        lock_acquired = await lock_repo.acquire_lock(lock_name, holder_id, 300)
        if lock_acquired:
            break
        if attempt < _LOCK_MAX_RETRIES:
            delay = _LOCK_RETRY_BASE_DELAY * (2**attempt)
            logger.debug(
                f"Lock contention for stats recalculation of project {project_id}; "
                f"retrying in {delay:.2f}s (attempt {attempt + 1}/{_LOCK_MAX_RETRIES})."
            )
            await asyncio.sleep(delay)
    if not lock_acquired:
        logger.warning(
            f"Could not acquire lock for stats recalculation of project {project_id} "
            f"after {_LOCK_MAX_RETRIES} retries. Another process is holding it; "
            f"stats may be stale until the next recalculation."
        )
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
        # Head first and alone records waiver outcomes and signatures: those describe head, and the
        # other passes then see the signatures head back-filled.
        if scan_id and not head_current:
            stats = await _restamp_scan(scan_id, db, waivers, fingerprint, finding_repo, waiver_repo)
            await project_repo.update_raw(project_id, {"$set": {"stats": stats.model_dump()}})
        for other_id in stale:
            await _restamp_scan(other_id, db, waivers, fingerprint, finding_repo, None)
        return stats

    finally:
        if lock_acquired:
            await lock_repo.release_lock(lock_name, holder_id)
            logger.debug(f"Released lock {lock_name} for project {project_id}")


async def recalculate_all_projects(db: AsyncIOMotorDatabase, waiver: Waiver) -> int:
    """Recalculate every project whose head or released scans hold a finding the changed global ``waiver`` can
    stamp; returns how many were recalculated. One failing project does not stop the others."""
    reach = waiver_reach_filter(waiver)
    if reach is None:
        logger.info("Global waiver %s can stamp no finding; no project to recalculate", waiver.id)
        return 0
    # Read up front: a cursor held open across the whole run times out on the server partway.
    project_ids = [project["_id"] async for project in db.projects.find({}, {"_id": 1})]
    recalculated = failed = 0
    for project_id in project_ids:
        try:
            recalculated += await recalculate_project_stats(project_id, db, reach) is not None
        except Exception:
            failed += 1
            logger.exception("Global waiver %s: recalculation failed for project %s", waiver.id, project_id)
    logger.info(
        "Global waiver %s: %d of %d projects recalculated, %d failed", waiver.id, recalculated, len(project_ids), failed
    )
    return recalculated
