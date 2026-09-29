import asyncio
import logging
import os

from motor.motor_asyncio import AsyncIOMotorDatabase

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
from app.services.waivers.apply import restamp_waivers

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
    finding_repo: FindingRepository,
    waiver_repo: WaiverRepository | None,
) -> Stats:
    """Re-apply the current waiver set to one scan and rewrite its stats from the result; ``waiver_repo``,
    when given, records what each waiver matched there."""
    await restamp_waivers(finding_repo, waiver_repo, scan_id, waivers)
    stats = await calculate_comprehensive_stats(db, scan_id)
    ignored_count = await finding_repo.count_waived(scan_id)
    await ScanRepository(db).update_raw(
        scan_id,
        {"$set": {"stats": stats.model_dump(), "ignored_count": ignored_count}},
    )
    return stats


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


async def recalculate_project_stats(project_id: str, db: AsyncIOMotorDatabase) -> Stats | None:
    """Recalculate a project's stats from its head scan and active waivers, and re-stamp the same
    waiver set onto the scans release mode reports.

    Resets ALL waivers for those scans and re-applies them under a distributed lock to
    prevent races when pods modify waivers concurrently. Returns None if project not found.
    """
    project_repo = ProjectRepository(db)
    finding_repo = FindingRepository(db)
    waiver_repo = WaiverRepository(db)
    lock_repo = DistributedLocksRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project:
        return None

    scan_id = await ScanRepository(db).get_latest_active_scan_id(project)
    released_ids = [rid for rid in await _released_analysis_ids(db, project_id) if rid != scan_id]
    if not scan_id and not released_ids:
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
        logger.info(
            f"Recalculating stats for project {project_id} (head {scan_id}, released {released_ids}) "
            f"with lock {lock_name}"
        )

        waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)
        # Head first and alone records waiver outcomes and signatures: those describe head, and the
        # released passes then see the signatures head back-filled.
        stats = await _restamp_scan(scan_id, db, waivers, finding_repo, waiver_repo) if scan_id else None
        for released_id in released_ids:
            await _restamp_scan(released_id, db, waivers, finding_repo, None)
        if stats is None:
            return None

        await project_repo.update_raw(project_id, {"$set": {"stats": stats.model_dump()}})

        logger.info(f"Stats updated for project {project_id}: {stats.model_dump()}")
        return stats

    finally:
        if lock_acquired:
            await lock_repo.release_lock(lock_name, holder_id)
            logger.debug(f"Released lock {lock_name} for project {project_id}")


async def recalculate_all_projects(db: AsyncIOMotorDatabase) -> int:
    """Recalculate stats for ALL projects; returns the number processed. Resource intensive."""
    logger.info("Starting global stats recalculation")
    count = 0
    async for project in db.projects.find({}, {"_id": 1}):
        await recalculate_project_stats(project["_id"], db)
        count += 1
    logger.info(f"Global stats recalculation completed: {count} projects processed")
    return count
