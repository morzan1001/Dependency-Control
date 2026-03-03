import logging
import os
import re
from typing import Any, Dict, List, Optional, Union

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import CVSS_SEVERITY_SCORES
from app.models.stats import Stats
from app.models.waiver import Waiver

logger = logging.getLogger(__name__)

# MongoDB aggregation field references / operators
MONGO_SEVERITY = "$severity"
MONGO_COND = "$cond"

# Waiver field mapping: waiver field -> finding query field
_WAIVER_FIELD_MAP = {
    "finding_id": "finding_id",
    "package_name": "component",
    "package_version": "version",
    "finding_type": "type",
}


def _strip_line_number(finding_id: str) -> Optional[str]:
    """Strip the trailing line number from a SAST finding ID to get the file-level prefix.

    SAST finding IDs end with ``-<line_number>``.  Stripping that suffix
    lets us match all findings for the same rule + file regardless of line.

    Example:
        ``BEARER-rule_id-src/file.js-102`` → ``BEARER-rule_id-src/file.js``
    """
    parts = finding_id.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return None


def _extract_rule_prefix(finding_id: str, component: str) -> Optional[str]:
    """Extract the scanner+rule prefix from a SAST/IAC finding ID.

    Given ``finding_id = {SCANNER}-{rule_id}-{file_path}-{line}``
    and ``component = {file_path}``, returns ``{SCANNER}-{rule_id}``.

    Used by "rule" scope waivers to match all findings for the same rule
    across all files in a project.

    Example:
        ``_extract_rule_prefix(
            "BEARER-javascript_lang_insufficiently_random_values-src/file.js-102",
            "src/file.js",
        )`` → ``"BEARER-javascript_lang_insufficiently_random_values"``
    """
    file_prefix = _strip_line_number(finding_id)
    if not file_prefix:
        return None
    suffix = f"-{component}"
    if file_prefix.endswith(suffix):
        return file_prefix[: -len(suffix)]
    return None


async def _resolve_active_scan_id(
    db: AsyncIOMotorDatabase, project_id: str, scan_id: str, deleted_branches: List[str]
) -> Optional[str]:
    """Resolve the active scan_id, skipping deleted branches if needed."""
    if not deleted_branches:
        return scan_id

    scan_doc = await db.scans.find_one({"_id": scan_id}, {"branch": 1})
    if not scan_doc or scan_doc.get("branch") not in deleted_branches:
        return scan_id

    active_scan = await db.scans.find_one(
        {"project_id": project_id, "branch": {"$nin": deleted_branches}, "status": "completed"},
        sort=[("created_at", -1)],
        projection={"_id": 1},
    )
    return active_scan["_id"] if active_scan else None


def _resolve_finding_id_query(
    finding_id: str,
    scope: str,
    component: str,
) -> str | Dict[str, str]:
    """Resolve the MongoDB query value for ``finding_id`` based on waiver scope."""
    if scope == "file":
        prefix = _strip_line_number(finding_id)
        if prefix:
            return {"$regex": f"^{re.escape(prefix)}-\\d+$"}
    elif scope == "rule":
        rule_prefix = _extract_rule_prefix(finding_id, component)
        if rule_prefix:
            return {"$regex": f"^{re.escape(rule_prefix)}-"}
    return finding_id


def _build_waiver_query(waiver: Waiver) -> Dict[str, Union[str, Dict[str, str]]]:
    """Build a finding query dict from a waiver's matching fields."""
    scope = waiver.scope or "finding"
    query: Dict[str, Union[str, Dict[str, str]]] = {}

    waiver_values = {
        "finding_id": waiver.finding_id,
        "package_name": waiver.package_name,
        "package_version": waiver.package_version,
        "finding_type": waiver.finding_type,
    }

    for waiver_field, query_field in _WAIVER_FIELD_MAP.items():
        value = waiver_values.get(waiver_field)
        if not value or value == "Unknown":
            continue

        # Rule-scope waivers must NOT filter by component (match all files)
        if waiver_field == "package_name" and scope == "rule":
            continue

        if waiver_field == "finding_id" and scope in ("file", "rule"):
            query[query_field] = _resolve_finding_id_query(
                value,
                scope,
                waiver.package_name or "",
            )
        else:
            query[query_field] = value

    return query


async def _apply_waivers(finding_repo: Any, scan_id: str, waivers: List[Waiver]) -> None:
    """Apply all waivers for a scan."""
    for waiver in waivers:
        query = _build_waiver_query(waiver)

        if waiver.vulnerability_id:
            await finding_repo.apply_vulnerability_waiver(
                scan_id=scan_id,
                vulnerability_id=waiver.vulnerability_id,
                waived=True,
                waiver_reason=waiver.reason,
            )
        else:
            await finding_repo.apply_finding_waiver(
                scan_id=scan_id,
                query=query,
                waived=True,
                waiver_reason=waiver.reason,
            )


def _build_stats_pipeline(scan_id: str) -> List[Dict[str, Any]]:
    """Build the MongoDB aggregation pipeline for stats calculation."""
    return [
        {"$match": {"scan_id": scan_id, "waived": False}},
        {
            "$project": {
                "severity": 1,
                "cvss_score": "$details.cvss_score",
                "calculated_score": {
                    "$switch": {
                        "branches": [
                            {"case": {"$eq": [MONGO_SEVERITY, sev]}, "then": CVSS_SEVERITY_SCORES[sev]}
                            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                        ],
                        "default": CVSS_SEVERITY_SCORES["UNKNOWN"],
                    }
                },
            }
        },
        {
            "$group": {
                "_id": None,
                "critical": {"$sum": {MONGO_COND: [{"$eq": [MONGO_SEVERITY, "CRITICAL"]}, 1, 0]}},
                "high": {"$sum": {MONGO_COND: [{"$eq": [MONGO_SEVERITY, "HIGH"]}, 1, 0]}},
                "medium": {"$sum": {MONGO_COND: [{"$eq": [MONGO_SEVERITY, "MEDIUM"]}, 1, 0]}},
                "low": {"$sum": {MONGO_COND: [{"$eq": [MONGO_SEVERITY, "LOW"]}, 1, 0]}},
                "info": {"$sum": {MONGO_COND: [{"$eq": [MONGO_SEVERITY, "INFO"]}, 1, 0]}},
                "unknown": {"$sum": {MONGO_COND: [{"$eq": [MONGO_SEVERITY, "UNKNOWN"]}, 1, 0]}},
                "risk_score": {"$sum": {"$toDouble": {"$ifNull": ["$cvss_score", "$calculated_score"]}}},
            }
        },
    ]


def _stats_from_result(stats_result: List[Dict[str, Any]]) -> Stats:
    """Create a Stats object from an aggregation result."""
    stats = Stats()
    if not stats_result:
        return stats
    res = stats_result[0]
    stats.critical = res.get("critical", 0)
    stats.high = res.get("high", 0)
    stats.medium = res.get("medium", 0)
    stats.low = res.get("low", 0)
    stats.info = res.get("info", 0)
    stats.unknown = res.get("unknown", 0)
    stats.risk_score = round(res.get("risk_score", 0.0), 1)
    return stats


async def recalculate_project_stats(project_id: str, db: AsyncIOMotorDatabase) -> Optional[Stats]:
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
    from app.repositories import (
        DistributedLocksRepository,
        FindingRepository,
        ProjectRepository,
        ScanRepository,
        WaiverRepository,
    )

    project_repo = ProjectRepository(db)
    finding_repo = FindingRepository(db)
    waiver_repo = WaiverRepository(db)
    lock_repo = DistributedLocksRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project or not project.latest_scan_id:
        return None

    scan_id = await _resolve_active_scan_id(db, project_id, project.latest_scan_id, project.deleted_branches or [])
    if not scan_id:
        return None

    # Acquire distributed lock to prevent race conditions
    lock_name = f"stats_recalc:{project_id}"
    holder_id = f"pod-{os.getenv('HOSTNAME', 'unknown')}-{os.getpid()}"

    lock_acquired = await lock_repo.acquire_lock(lock_name, holder_id, 300)
    if not lock_acquired:
        logger.warning(
            f"Could not acquire lock for stats recalculation of project {project_id}. "
            f"Another process is already recalculating stats."
        )
        return None

    try:
        logger.info(f"Recalculating stats for project {project_id} (scan {scan_id}) with lock {lock_name}")

        # 1. Reset waivers for this scan
        await finding_repo.update_many({"scan_id": scan_id}, {"waived": False, "waiver_reason": None})

        # 2. Fetch and apply active waivers
        waivers = await waiver_repo.find_active_for_project(project_id, include_global=True)
        await _apply_waivers(finding_repo, scan_id, waivers)

        # 3. Calculate stats
        pipeline = _build_stats_pipeline(scan_id)
        stats_result = await finding_repo.aggregate(pipeline, limit=1)
        stats = _stats_from_result(stats_result)

        # 4. Calculate ignored count and update Scan and Project
        ignored_count = await finding_repo.count({"scan_id": scan_id, "waived": True})

        scan_repo = ScanRepository(db)
        await scan_repo.update_raw(
            scan_id,
            {"$set": {"stats": stats.model_dump(), "ignored_count": ignored_count}},
        )

        await project_repo.update_raw(project_id, {"$set": {"stats": stats.model_dump()}})

        logger.info(f"Stats updated for project {project_id}: {stats.model_dump()}")
        return stats

    finally:
        if lock_acquired:
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
