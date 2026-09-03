"""Release lookup and the single resolver for 'which scan counts for this project'."""

from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import ensure_utc
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT, SCAN_USABLE_STATUSES
from app.repositories import ProjectRepository, ScanRepository

_MAX_RESCAN_HOPS = 10
_CHAIN_PROJECTION = {"_id": 1, "latest_rescan_id": 1, "status": 1, "created_at": 1}
_UNDATED = datetime.min.replace(tzinfo=timezone.utc)


def _created_at(doc: dict[str, Any]) -> datetime:
    # A scan with no created_at sorts oldest, so it wins only when its chain holds nothing else.
    return ensure_utc(doc.get("created_at")) or _UNDATED


async def effective_scan_ids(db: AsyncIOMotorDatabase, scan_ids: Iterable[str]) -> dict[str, str]:
    """The freshest readable analysis of each released artefact.

    Rescans chain — each is created from the project's newest usable scan, so the released scan's
    latest_rescan_id never advances past the first link — and the walk follows unusable links too,
    or a failed rescan would hide the good one behind it. Bounded, so a cyclic pointer cannot hang a
    request. A release with no usable scan in its chain, like one whose scan retention deleted, is
    absent rather than a misleading id.
    """
    frontier: dict[str, str] = {scan_id: scan_id for scan_id in scan_ids}
    visited: set[str] = set()
    freshest: dict[str, dict[str, Any]] = {}

    for _hop in range(_MAX_RESCAN_HOPS + 1):
        if not frontier:
            break
        visited.update(frontier)
        next_frontier: dict[str, str] = {}
        async for doc in db.scans.find({"_id": {"$in": list(frontier)}}, _CHAIN_PROJECTION):
            released_id = frontier[doc["_id"]]
            if doc.get("status") in SCAN_USABLE_STATUSES:
                incumbent = freshest.get(released_id)
                if incumbent is None or _created_at(doc) > _created_at(incumbent):
                    freshest[released_id] = doc
            rescan_id = doc.get("latest_rescan_id")
            if rescan_id and rescan_id not in visited:
                next_frontier[rescan_id] = released_id
        frontier = next_frontier

    return {released_id: doc["_id"] for released_id, doc in freshest.items()}


async def latest_release_scan(db: AsyncIOMotorDatabase, project_id: str, environment: str) -> str | None:
    """The scan running in one environment. Ordered by released_at, so re-marking an older scan is
    the rollback path and needs no extra flag."""
    row = await db.releases.find_one(
        {"project_id": project_id, "environment": environment},
        sort=[("released_at", -1)],
    )
    if row is None:
        return None
    return (await effective_scan_ids(db, [row["scan_id"]])).get(row["scan_id"])


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
    effective = await effective_scan_ids(db, set(released.values()))
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
