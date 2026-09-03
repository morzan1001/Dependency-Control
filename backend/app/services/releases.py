"""Release lookup and the single resolver for 'which scan counts for this project'."""

from collections.abc import Iterable, Sequence
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT, SCAN_USABLE_STATUSES
from app.repositories import ProjectRepository, ScanRepository

_RELEASED_SCAN_PROJECTION = {"_id": 1, "latest_rescan_id": 1, "status": 1}
_SCAN_ID_ONLY_PROJECTION = {"_id": 1}


async def _effective_scan_ids(db: AsyncIOMotorDatabase, scan_ids: Iterable[str]) -> dict[str, str]:
    """The freshest scan of the released artefact whose analysis can be read: its latest rescan when
    that rescan is usable, else the released scan itself when it is. latest_rescan_id is written when
    the rescan is created, so following it unconditionally would report a running rescan's empty
    stats as zero findings in the environment. A scan with no usable analysis at all, and one that
    retention has already deleted, are both absent from the result rather than a misleading id."""
    released = {
        doc["_id"]: doc async for doc in db.scans.find({"_id": {"$in": list(scan_ids)}}, _RELEASED_SCAN_PROJECTION)
    }
    rescan_ids = {doc["latest_rescan_id"] for doc in released.values() if doc.get("latest_rescan_id")}
    usable_rescans: set[str] = set()
    if rescan_ids:
        usable = {"_id": {"$in": list(rescan_ids)}, "status": {"$in": SCAN_USABLE_STATUSES}}
        usable_rescans = {doc["_id"] async for doc in db.scans.find(usable, _SCAN_ID_ONLY_PROJECTION)}

    effective: dict[str, str] = {}
    for scan_id, doc in released.items():
        rescan_id = doc.get("latest_rescan_id")
        if rescan_id in usable_rescans:
            effective[scan_id] = rescan_id
        elif doc.get("status") in SCAN_USABLE_STATUSES:
            effective[scan_id] = scan_id
    return effective


async def latest_release_scan(db: AsyncIOMotorDatabase, project_id: str, environment: str) -> str | None:
    """The scan running in one environment. Ordered by released_at, so re-marking an older scan is
    the rollback path and needs no extra flag."""
    row = await db.releases.find_one(
        {"project_id": project_id, "environment": environment},
        sort=[("released_at", -1)],
    )
    if row is None:
        return None
    return (await _effective_scan_ids(db, [row["scan_id"]])).get(row["scan_id"])


async def release_environments(db: AsyncIOMotorDatabase, project_id: str) -> list[str]:
    environments: list[str] = await db.releases.distinct("environment", {"project_id": project_id})
    return sorted(environments)


async def _release_scan_ids(
    db: AsyncIOMotorDatabase, project_ids: Sequence[str] | None, environment: str
) -> dict[str, str]:
    match: dict[str, Any] = {"environment": environment}
    if project_ids is not None:
        match["project_id"] = {"$in": list(project_ids)}
    pipeline: list[dict[str, Any]] = [
        {"$match": match},
        {"$sort": {"released_at": -1}},
        {"$group": {"_id": "$project_id", "scan_id": {"$first": "$scan_id"}}},
    ]
    released = {row["_id"]: row["scan_id"] async for row in db.releases.aggregate(pipeline)}
    if not released:
        return {}
    effective = await _effective_scan_ids(db, set(released.values()))
    return {project_id: effective[scan_id] for project_id, scan_id in released.items() if scan_id in effective}


async def resolve_scan_ids(
    db: AsyncIOMotorDatabase,
    project_ids: Sequence[str] | None,
    *,
    release_environment: str | None = None,
) -> dict[str, str]:
    """project_id -> the scan that represents it; None project_ids means every project.
    Projects that resolve to no scan are omitted, so callers reporting a scope size must count elsewhere."""
    if project_ids is not None and not project_ids:
        return {}

    if release_environment is not None:
        return await _release_scan_ids(db, project_ids, release_environment)

    query: dict[str, Any] = {} if project_ids is None else {"_id": {"$in": list(project_ids)}}
    projects = await ProjectRepository(db).find_many_with_scan_id(query, limit=ANALYTICS_MAX_QUERY_LIMIT)
    return await ScanRepository(db).get_latest_active_scan_ids(projects)
