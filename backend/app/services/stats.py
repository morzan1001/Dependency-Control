import logging
from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import CVSS_SEVERITY_SCORES
from app.models.stats import Stats

logger = logging.getLogger(__name__)

# Severity level constants for MongoDB queries
_SEVERITY_CRITICAL = "CRITICAL"
_SEVERITY_HIGH = "HIGH"
_SEVERITY_MEDIUM = "MEDIUM"
_SEVERITY_LOW = "LOW"
_SEVERITY_INFO = "INFO"
_SEVERITY_UNKNOWN = "UNKNOWN"


async def recalculate_project_stats(
    project_id: str, db: AsyncIOMotorDatabase
) -> Optional[Stats]:
    """
    Recalculates statistics for a project based on its latest scan and active waivers.
    This should be called whenever waivers are added, updated, or removed.

    Args:
        project_id: The ID of the project to recalculate stats for
        db: Database connection

    Returns:
        The calculated Stats object, or None if project not found
    """
    project = await db.projects.find_one({"_id": project_id})
    if not project or not project.get("latest_scan_id"):
        return None

    scan_id = project["latest_scan_id"]
    logger.info(f"Recalculating stats for project {project_id} (scan {scan_id})")

    # 1. Reset waivers for this scan
    await db.findings.update_many(
        {"scan_id": scan_id}, {"$set": {"waived": False, "waiver_reason": None}}
    )

    # 2. Fetch active waivers
    # Note: We need to handle both global waivers (project_id=None) and project-specific waivers
    waivers_cursor = db.waivers.find(
        {"$or": [{"project_id": project_id}, {"project_id": None}]}
    )

    waivers = await waivers_cursor.to_list(None)

    # Filter expired waivers
    now = datetime.now(timezone.utc)
    active_waivers = [
        w
        for w in waivers
        if not (
            w.get("expiration_date")
            and w["expiration_date"].replace(tzinfo=timezone.utc) < now
        )
    ]

    # 3. Apply waivers
    for waiver in active_waivers:
        query = {"scan_id": scan_id}
        if waiver.get("finding_id"):
            query["finding_id"] = waiver["finding_id"]
        if waiver.get("package_name"):
            query["component"] = waiver["package_name"]
        if waiver.get("package_version"):
            query["version"] = waiver["package_version"]
        if waiver.get("finding_type"):
            query["type"] = waiver["finding_type"]

        await db.findings.update_many(
            query, {"$set": {"waived": True, "waiver_reason": waiver.get("reason")}}
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
                                "case": {"$eq": ["$severity", _SEVERITY_CRITICAL]},
                                "then": CVSS_SEVERITY_SCORES[_SEVERITY_CRITICAL],
                            },
                            {
                                "case": {"$eq": ["$severity", _SEVERITY_HIGH]},
                                "then": CVSS_SEVERITY_SCORES[_SEVERITY_HIGH],
                            },
                            {
                                "case": {"$eq": ["$severity", _SEVERITY_MEDIUM]},
                                "then": CVSS_SEVERITY_SCORES[_SEVERITY_MEDIUM],
                            },
                            {
                                "case": {"$eq": ["$severity", _SEVERITY_LOW]},
                                "then": CVSS_SEVERITY_SCORES[_SEVERITY_LOW],
                            },
                        ],
                        "default": CVSS_SEVERITY_SCORES[_SEVERITY_UNKNOWN],
                    }
                },
            }
        },
        {
            "$group": {
                "_id": None,
                "critical": {
                    "$sum": {
                        "$cond": [{"$eq": ["$severity", _SEVERITY_CRITICAL]}, 1, 0]
                    }
                },
                "high": {
                    "$sum": {"$cond": [{"$eq": ["$severity", _SEVERITY_HIGH]}, 1, 0]}
                },
                "medium": {
                    "$sum": {"$cond": [{"$eq": ["$severity", _SEVERITY_MEDIUM]}, 1, 0]}
                },
                "low": {
                    "$sum": {"$cond": [{"$eq": ["$severity", _SEVERITY_LOW]}, 1, 0]}
                },
                "info": {
                    "$sum": {"$cond": [{"$eq": ["$severity", _SEVERITY_INFO]}, 1, 0]}
                },
                "unknown": {
                    "$sum": {"$cond": [{"$eq": ["$severity", _SEVERITY_UNKNOWN]}, 1, 0]}
                },
                "risk_score": {
                    "$sum": {
                        "$toDouble": {"$ifNull": ["$cvss_score", "$calculated_score"]}
                    }
                },
            }
        },
    ]

    stats_result = await db.findings.aggregate(pipeline).to_list(1)

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

    # Calculate ignored count
    ignored_count = await db.findings.count_documents(
        {"scan_id": scan_id, "waived": True}
    )

    # 5. Update Scan and Project
    await db.scans.update_one(
        {"_id": scan_id},
        {"$set": {"stats": stats.model_dump(), "ignored_count": ignored_count}},
    )

    await db.projects.update_one(
        {"_id": project_id}, {"$set": {"stats": stats.model_dump()}}
    )

    logger.info(f"Stats updated for project {project_id}: {stats.model_dump()}")
    return stats


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
