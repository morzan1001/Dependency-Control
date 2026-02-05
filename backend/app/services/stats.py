import logging
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import CVSS_SEVERITY_SCORES
from app.models.stats import Stats

logger = logging.getLogger(__name__)


async def recalculate_project_stats(
    project_id: str, db: AsyncIOMotorDatabase
) -> Optional[Stats]:
    """
    Recalculates statistics for a project based on its latest scan and active waivers.
    This should be called whenever waivers are added, updated, or removed.

    WARNING: This function resets ALL waivers for the scan and re-applies them.
    This is a CRITICAL operation protected by distributed locking to prevent
    race conditions when multiple pods modify waivers concurrently.

    Args:
        project_id: The ID of the project to recalculate stats for
        db: Database connection

    Returns:
        The calculated Stats object, or None if project not found
    """
    import os
    from app.repositories import (
        DistributedLocksRepository,
        FindingRepository,
        ProjectRepository,
        WaiverRepository,
    )

    project_repo = ProjectRepository(db)
    finding_repo = FindingRepository(db)
    waiver_repo = WaiverRepository(db)
    lock_repo = DistributedLocksRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project or not project.latest_scan_id:
        return None

    scan_id = project.latest_scan_id

    # Acquire distributed lock to prevent race conditions
    lock_name = f"stats_recalc:{project_id}"
    holder_id = f"pod-{os.getenv('HOSTNAME', 'unknown')}-{os.getpid()}"
    lock_ttl = 300  # 5 minutes - should be enough for stats recalculation

    if not await lock_repo.acquire_lock(lock_name, holder_id, lock_ttl):
        logger.warning(
            f"Could not acquire lock for stats recalculation of project {project_id}. "
            f"Another process is already recalculating stats."
        )
        # Return None to signal that recalculation is already in progress
        return None

    try:
        logger.info(
            f"Recalculating stats for project {project_id} (scan {scan_id}) "
            f"with lock {lock_name}"
        )

        # 1. Reset waivers for this scan
        await finding_repo.update_many(
            {"scan_id": scan_id}, {"waived": False, "waiver_reason": None}
        )

        # 2. Fetch active waivers via repository
        waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)

        # 3. Apply waivers via FindingRepository
        for waiver in waivers:
            query = {}
            if waiver.get("finding_id"):
                query["finding_id"] = waiver["finding_id"]
            if waiver.get("package_name"):
                query["component"] = waiver["package_name"]
            if waiver.get("package_version"):
                query["version"] = waiver["package_version"]
            if waiver.get("finding_type"):
                query["type"] = waiver["finding_type"]

            vulnerability_id = waiver.get("vulnerability_id")
            if vulnerability_id:
                # Vulnerability-level waiver (uses array_filters)
                await finding_repo.apply_vulnerability_waiver(
                    scan_id=scan_id,
                    vulnerability_id=vulnerability_id,
                    waived=True,
                    waiver_reason=waiver.get("reason"),
                )
            else:
                # Finding-level waiver
                await finding_repo.apply_finding_waiver(
                    scan_id=scan_id,
                    query=query,
                    waived=True,
                    waiver_reason=waiver.get("reason"),
                )

        # 4. Calculate stats using CVSS severity scores from constants
        pipeline = [
            {"$match": {"scan_id": scan_id, "waived": False}},
            {
                "$project": {
                    "severity": 1,
                    "cvss_score": "$details.cvss_score",
                    "calculated_score": {
                        "$switch": {
                            "branches": [
                                {
                                    "case": {"$eq": ["$severity", "CRITICAL"]},
                                    "then": CVSS_SEVERITY_SCORES["CRITICAL"],
                                },
                                {
                                    "case": {"$eq": ["$severity", "HIGH"]},
                                    "then": CVSS_SEVERITY_SCORES["HIGH"],
                                },
                                {
                                    "case": {"$eq": ["$severity", "MEDIUM"]},
                                    "then": CVSS_SEVERITY_SCORES["MEDIUM"],
                                },
                                {
                                    "case": {"$eq": ["$severity", "LOW"]},
                                    "then": CVSS_SEVERITY_SCORES["LOW"],
                                },
                            ],
                            "default": CVSS_SEVERITY_SCORES["UNKNOWN"],
                        }
                    },
                }
            },
            {
                "$group": {
                    "_id": None,
                    "critical": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}
                    },
                    "high": {"$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}},
                    "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}},
                    "low": {"$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}},
                    "info": {"$sum": {"$cond": [{"$eq": ["$severity", "INFO"]}, 1, 0]}},
                    "unknown": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "UNKNOWN"]}, 1, 0]}
                    },
                    "risk_score": {
                        "$sum": {
                            "$toDouble": {"$ifNull": ["$cvss_score", "$calculated_score"]}
                        }
                    },
                }
            },
        ]

        stats_result = await finding_repo.aggregate(pipeline, limit=1)

        stats = Stats()
        if stats_result:
            res = stats_result[0]
            stats.critical = res.get("critical", 0)
            stats.high = res.get("high", 0)
            stats.medium = res.get("medium", 0)
            stats.low = res.get("low", 0)
            stats.info = res.get("info", 0)
            stats.unknown = res.get("unknown", 0)
            stats.risk_score = round(res.get("risk_score", 0.0), 1)

        # Calculate ignored count via repository
        ignored_count = await finding_repo.count(
            {"scan_id": scan_id, "waived": True}
        )

        # 5. Update Scan and Project via repositories
        from app.repositories import ScanRepository

        scan_repo = ScanRepository(db)
        await scan_repo.update_raw(
            scan_id,
            {"$set": {"stats": stats.model_dump(), "ignored_count": ignored_count}},
        )

        await project_repo.update_raw(
            project_id, {"$set": {"stats": stats.model_dump()}}
        )

        logger.info(f"Stats updated for project {project_id}: {stats.model_dump()}")
        return stats

    finally:
        # Always release the lock, even if an exception occurs
        await lock_repo.release_lock(lock_name)
        logger.debug(f"Released lock {lock_name} for project {project_id}")


async def recalculate_all_projects(db: AsyncIOMotorDatabase) -> int:
    """
    Recalculates statistics for ALL projects.
    Use with caution, as this can be resource intensive.

    Args:
        db: Database connection

    Returns:
        Number of projects recalculated
    """
    logger.info("Starting global stats recalculation")
    count = 0
    async for project in db.projects.find({}, {"_id": 1}):
        await recalculate_project_stats(project["_id"], db)
        count += 1
    logger.info(f"Global stats recalculation completed: {count} projects processed")
    return count
