"""Release lookup and the single resolver for 'which scan counts for this project'."""

from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import ensure_utc
from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT, MAX_RESCAN_HOPS, SCAN_USABLE_STATUSES
from app.repositories import ProjectRepository, ScanRepository
from app.schemas.projections import ProjectWithScanId

_CHAIN_PROJECTION = {"_id": 1, "latest_rescan_id": 1, "status": 1, "created_at": 1}
_UNDATED = datetime.min.replace(tzinfo=timezone.utc)


def _created_at(doc: dict[str, Any]) -> datetime:
    # A scan with no created_at sorts oldest, so it wins only when its chain holds nothing else.
    return ensure_utc(doc.get("created_at")) or _UNDATED


def _is_fresher(doc: dict[str, Any], incumbent: dict[str, Any]) -> bool:
    """Newer wins; on a tie the lower _id does, because BSON dates are milliseconds and two links
    stamped inside one cannot be told apart by their date alone."""
    doc_at, incumbent_at = _created_at(doc), _created_at(incumbent)
    if doc_at != incumbent_at:
        return doc_at > incumbent_at
    return str(doc["_id"]) < str(incumbent["_id"])


async def effective_scan_ids(db: AsyncIOMotorDatabase, scan_ids: Iterable[str]) -> dict[str, str]:
    """The freshest readable analysis of each released artefact.

    Rescans chain — a rescan of a release is created from the marked scan (_rescan_targets), so the
    released scan's latest_rescan_id is overwritten rather than extended and never advances past the
    first link — and the walk follows unusable links too, or a failed rescan would hide the good one
    behind it. Bounded, so a cyclic pointer cannot hang a request. A release with no usable scan in
    its chain, like one whose scan retention deleted, is absent rather than a misleading id.
    """
    frontier: dict[str, str] = {scan_id: scan_id for scan_id in scan_ids}
    visited: set[str] = set()
    freshest: dict[str, dict[str, Any]] = {}

    for _hop in range(MAX_RESCAN_HOPS + 1):
        if not frontier:
            break
        visited.update(frontier)
        next_frontier: dict[str, str] = {}
        async for doc in db.scans.find({"_id": {"$in": list(frontier)}}, _CHAIN_PROJECTION):
            released_id = frontier[doc["_id"]]
            if doc.get("status") in SCAN_USABLE_STATUSES:
                incumbent = freshest.get(released_id)
                if incumbent is None or _is_fresher(doc, incumbent):
                    freshest[released_id] = doc
            rescan_id = doc.get("latest_rescan_id")
            if rescan_id and rescan_id not in visited:
                next_frontier[rescan_id] = released_id
        frontier = next_frontier

    return {released_id: doc["_id"] for released_id, doc in freshest.items()}


async def release_protected_scan_ids(db: AsyncIOMotorDatabase, scan_ids: Sequence[str]) -> set[str]:
    """Which of these scans a release cannot lose: the marked scan and the analysis it resolves to.

    Keyed on db.releases rather than on the denormalised Scan.is_release, because every writer of
    that flag is a two-step sequence whose second step can be lost, and a row without a flag is
    then indistinguishable from a scan nothing ever released.
    """
    candidates = list(scan_ids)
    if not candidates:
        return set()
    candidate_set = set(candidates)
    # Both rescan creators re-root original_scan_id at the lineage root, so a release's chain is one
    # link deep and one backward hop reaches every scan effective_scan_ids can answer with.
    chain_parents = await db.scans.distinct("_id", {"latest_rescan_id": {"$in": candidates}})
    marked = set(await db.releases.distinct("scan_id", {"scan_id": {"$in": candidates + chain_parents}}))
    protected = candidate_set & marked
    released_parents = sorted(marked & set(chain_parents))
    if not released_parents:
        return protected
    current_analysis = await db.scans.distinct("latest_rescan_id", {"_id": {"$in": released_parents}})
    return protected | (candidate_set & set(current_analysis))


async def latest_release_scan(db: AsyncIOMotorDatabase, project_id: str, environment: str) -> str | None:
    """The scan running in one environment. Ordered by released_at, so re-marking an older scan is
    the rollback path and needs no extra flag."""
    row = await db.releases.find_one(
        {"project_id": project_id, "environment": environment},
        # Same tie-break as the analytics path, or two marks landing in one millisecond answer
        # "what is in production" differently depending on which endpoint is asked.
        sort=[("released_at", -1), ("_id", 1)],
    )
    if row is None:
        return None
    return (await effective_scan_ids(db, [row["scan_id"]])).get(row["scan_id"])


async def released_scan_ids(db: AsyncIOMotorDatabase, project_id: str) -> dict[str, str]:
    """environment -> the scan that was marked for it, before any rescan chain."""
    pipeline: list[dict[str, Any]] = [
        {"$match": {"project_id": project_id}},
        # Matches the residual releases_latest_lookup order after the project_id equality, so the
        # sort is index-served instead of ranking every release row the project ever had.
        {"$sort": {"environment": 1, "released_at": -1}},
        {"$group": {"_id": "$environment", "scan_id": {"$first": "$scan_id"}}},
    ]
    marked = {row["_id"]: row["scan_id"] async for row in db.releases.aggregate(pipeline)}
    return {environment: marked[environment] for environment in sorted(marked)}


async def _release_scan_ids(
    db: AsyncIOMotorDatabase, project_ids: Sequence[str] | None, environment: str
) -> dict[str, str]:
    match: dict[str, Any] = {"environment": environment}
    if project_ids is not None:
        match["project_id"] = {"$in": list(project_ids)}
    pipeline: list[dict[str, Any]] = [
        {"$match": match},
        # _id breaks released_at ties so a rollback marked with an explicit timestamp cannot make
        # analytics pick a different scan on every request. The sort is unindexed either way.
        {"$sort": {"released_at": -1, "_id": 1}},
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
    projects: Sequence[ProjectWithScanId] | None = None,
) -> dict[str, str]:
    """project_id -> the scan that represents it; None project_ids means every project.
    Projects that resolve to no scan are omitted, so callers reporting a scope size must count
    elsewhere. A caller that already read the scope passes it as projects to spare the head path
    its own read; the release path ignores it."""
    if project_ids is not None and not project_ids:
        return {}

    if release_environment is not None:
        return await _release_scan_ids(db, project_ids, release_environment)

    if projects is None:
        query: dict[str, Any] = {} if project_ids is None else {"_id": {"$in": list(project_ids)}}
        projects = await ProjectRepository(db).find_many_with_scan_id(query, limit=ANALYTICS_MAX_QUERY_LIMIT)
    return await ScanRepository(db).get_latest_active_scan_ids(list(projects))
