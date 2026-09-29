"""Release lookup and the single resolver for 'which scan counts for this project'."""

import logging
from collections.abc import Sequence
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import abatched
from app.core.constants import RELEASE_FLAG_RECONCILE_BATCH_SIZE
from app.core.init_db import RELEASES_ENVIRONMENT_SORT, RELEASES_LATEST_LOOKUP_KEY
from app.repositories.releases import ReleaseRepository
from app.repositories.scans import ScanRepository
from app.schemas.projections import ProjectWithScanId
from app.services.analytics.scopes import read_scope_projects

logger = logging.getLogger(__name__)


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
    # link deep and one backward hop reaches every scan freshest_in_lineage can answer with.
    chain_parents = await db.scans.distinct("_id", {"latest_rescan_id": {"$in": candidates}})
    marked = await ReleaseRepository(db).released_among(candidates + chain_parents)
    protected = candidate_set & marked
    released_parents = sorted(marked & set(chain_parents))
    if not released_parents:
        return protected
    current_analysis = await db.scans.distinct("latest_rescan_id", {"_id": {"$in": released_parents}})
    return protected | (candidate_set & set(current_analysis))


async def reconcile_release_flags(db: AsyncIOMotorDatabase) -> tuple[int, int]:
    """Bring Scan.is_release back to what db.releases says. Returns (cleared, restored).

    Every writer records the row and then the flag, so either half can be the one lost. Both
    directions are reconciled, so a clear that races an in-flight mark is itself repaired on the
    next pass instead of becoming the next divergence.
    """
    release_repo = ReleaseRepository(db)
    cleared = 0
    # Exactly true, so the scans_released_list partial index serves the sweep; another spelling
    # costs a listing row, not a scan, because retention keys its exemption on db.releases.
    flagged = (str(doc["_id"]) async for doc in db.scans.find({"is_release": True}, {"_id": 1}))
    async for scan_ids in abatched(flagged, RELEASE_FLAG_RECONCILE_BATCH_SIZE):
        released = await release_repo.released_among(scan_ids)
        stale = [scan_id for scan_id in scan_ids if scan_id not in released]
        if stale:
            result = await db.scans.update_many({"_id": {"$in": stale}}, {"$set": {"is_release": False}})
            cleared += result.modified_count

    restored = 0
    marked = (
        str(doc["scan_id"]) async for doc in db.releases.find({}, {"scan_id": 1}) if doc.get("scan_id") is not None
    )
    async for scan_ids in abatched(marked, RELEASE_FLAG_RECONCILE_BATCH_SIZE):
        result = await db.scans.update_many(
            {"_id": {"$in": scan_ids}, "is_release": {"$ne": True}}, {"$set": {"is_release": True}}
        )
        restored += result.modified_count

    if cleared or restored:
        logger.info("release flag reconcile: cleared %d, restored %d", cleared, restored)
    return cleared, restored


async def released_scan_ids(db: AsyncIOMotorDatabase, project_id: str) -> dict[str, str]:
    """environment -> the scan that was marked for it, before any rescan chain."""
    pipeline: list[dict[str, Any]] = [
        {"$match": {"project_id": project_id}},
        # Index-served per-environment pick.
        {"$sort": dict(RELEASES_ENVIRONMENT_SORT)},
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
        # Index-served per-project pick.
        {"$sort": dict(RELEASES_LATEST_LOOKUP_KEY)},
        {"$group": {"_id": "$project_id", "scan_id": {"$first": "$scan_id"}}},
    ]
    released = {row["_id"]: row["scan_id"] async for row in db.releases.aggregate(pipeline)}
    if not released:
        return {}
    effective = await ScanRepository(db).freshest_in_lineage(set(released.values()))
    return {project_id: effective[scan_id].scan_id for project_id, scan_id in released.items() if scan_id in effective}


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
        projects = await read_scope_projects(db, query)
    return await ScanRepository(db).get_latest_active_scan_ids(list(projects))
