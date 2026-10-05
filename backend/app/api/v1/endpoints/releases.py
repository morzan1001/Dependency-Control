"""Mark, unmark and list the releases of a project."""

import logging
from datetime import datetime, timezone
from typing import Annotated, Any

import pymongo
from fastapi import HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep, ProjectWriteDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.pagination import page_meta
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404, RESP_AUTH_404_409
from app.core import ensure_utc
from app.core.constants import (
    DEFAULT_RELEASE_ENVIRONMENT,
    RELEASE_ENVIRONMENT_PATTERN,
    SCAN_STATUS_FAILED,
    SCANS_TIP_SORT,
)
from app.models.release import Release, release_identity
from app.repositories.releases import ReleaseRepository
from app.repositories.scans import LineageAnalysis, ScanRepository
from app.schemas.pagination import Page
from app.schemas.release import ReleaseItem, ReleaseMarkRequest, ReleaseUnmarkResponse

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_SCAN_FIELDS = {"_id": 1, "commit_hash": 1, "branch": 1, "status": 1}
_DEFAULT_PAGE_SIZE = 20
_MAX_PAGE_SIZE = 100

_EnvironmentQuery = Annotated[str, Query(pattern=RELEASE_ENVIRONMENT_PATTERN)]
_OptionalEnvironmentQuery = Annotated[str | None, Query(pattern=RELEASE_ENVIRONMENT_PATTERN)]


def _to_item(row: dict[str, Any], scan: dict[str, Any], analysis: LineageAnalysis | None) -> ReleaseItem:
    return ReleaseItem(
        scan_id=row["scan_id"],
        project_id=row["project_id"],
        environment=row["environment"],
        version=row.get("version"),
        released_at=row["released_at"],
        commit_hash=scan.get("commit_hash"),
        branch=scan.get("branch"),
        scan_status=scan.get("status"),
        analysis_scan_id=analysis.scan_id if analysis else None,
        analysis_chain_bounded=bool(analysis and analysis.chain_bounded),
    )


async def _to_items(db: AsyncIOMotorDatabase, rows: list[dict[str, Any]]) -> list[ReleaseItem]:
    if not rows:
        return []
    scan_ids = {row["scan_id"] for row in rows}
    scan_repo = ScanRepository(db)
    scans = {
        doc["_id"]: doc
        for doc in await scan_repo.find_many_raw({"_id": {"$in": list(scan_ids)}}, projection=_SCAN_FIELDS)
    }
    # The resolver's own chain walk, so a release names the scan analytics actually reports.
    analysis = await scan_repo.freshest_in_lineage(scan_ids)
    return [_to_item(row, scans.get(row["scan_id"], {}), analysis.get(row["scan_id"])) for row in rows]


@router.post(
    "/{project_id}/releases",
    summary="Mark a commit's scan as released",
    status_code=201,
    responses=RESP_AUTH_404_409,
)
async def mark_release(
    project_id: ProjectWriteDep,
    payload: ReleaseMarkRequest,
    db: DatabaseDep,
) -> ReleaseItem:
    """Mark the newest build scan of a commit as running in an environment.

    The CD stage knows the commit it deployed, not our scan id, and may deploy before analysis
    finishes — a mark states where an artefact runs, not what we know about it. Re-scans are excluded
    because they copy the commit verbatim with a fresh created_at, so re-marking an already-rescanned
    commit would otherwise resolve to a different scan and open a second record for one deployment.
    Re-marking is the rollback path: the older scan's own record wins on a fresher released_at.
    A failed build is marked only when the commit has no other build, as it holds no analysis.
    """
    builds = {"project_id": project_id, "commit_hash": payload.commit_hash, "is_rescan": {"$ne": True}}
    scan_repo = ScanRepository(db)
    scan = await scan_repo.find_one(
        {**builds, "status": {"$ne": SCAN_STATUS_FAILED}}, sort=SCANS_TIP_SORT
    ) or await scan_repo.find_one(builds, sort=SCANS_TIP_SORT)
    if not scan:
        raise HTTPException(status_code=404, detail=f"No scan found for commit {payload.commit_hash}")

    scan_id = str(scan["_id"])
    environment, version = release_identity(payload.environment, payload.version, scan.get("commit_tag"))
    released_at = ensure_utc(payload.released_at) or datetime.now(timezone.utc)

    row = await ReleaseRepository(db).record(
        Release(
            project_id=project_id,
            environment=environment,
            version=version,
            scan_id=scan_id,
            released_at=released_at,
        )
    )
    await db.scans.update_one({"_id": scan_id}, {"$set": {"is_release": True}})
    logger.info(
        "release.mark",
        extra={"project_id": project_id, "scan_id": scan_id, "environment": environment},
    )

    # The stored row rather than an echo: an unversioned re-mark keeps the version the deploy job
    # recorded, and that fallback belongs to the repository alone.
    if row is None:
        raise HTTPException(status_code=409, detail=f"The release of {scan_id} to {environment} was withdrawn")
    return _to_item(row, scan, (await scan_repo.freshest_in_lineage([scan_id])).get(scan_id))


@router.delete(
    "/{project_id}/scans/{scan_id}/release",
    summary="Withdraw a scan from an environment",
    responses=RESP_AUTH_404,
)
async def unmark_release(
    project_id: ProjectWriteDep,
    scan_id: str,
    db: DatabaseDep,
    environment: _EnvironmentQuery = DEFAULT_RELEASE_ENVIRONMENT,
) -> ReleaseUnmarkResponse:
    """Remove one environment's release record, the inverse of a mark of the same environment."""
    release_repo = ReleaseRepository(db)
    remaining = await release_repo.withdraw(project_id, environment, scan_id)
    if remaining is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} is not released to {environment}")
    # is_release denormalises "this scan has a release record" for the scans_released_list partial
    # index, so it is recomputed rather than cleared: a scan still released to another environment
    # has to stay indexed. Ingest never demotes; reconcile_release_flags is the other path that does.
    if not remaining:
        await db.scans.update_one({"_id": scan_id, "project_id": project_id}, {"$set": {"is_release": False}})

    # Marks are history, so withdrawing the newest uncovers the one below it and the environment
    # goes on reporting a release the operator did not choose. Read it back and say which.
    uncovered = await release_repo.latest_for_environment(project_id, environment)
    environment_release = (await _to_items(db, [uncovered]))[0] if uncovered else None

    logger.info(
        "release.unmark",
        extra={
            "project_id": project_id,
            "scan_id": scan_id,
            "environment": environment,
            "environment_release_scan_id": environment_release.scan_id if environment_release else None,
        },
    )
    return ReleaseUnmarkResponse(
        scan_id=scan_id,
        environment=environment,
        is_release=bool(remaining),
        remaining_environments=remaining,
        environment_release=environment_release,
    )


@router.get("/{project_id}/releases", summary="List releases", responses=RESP_AUTH_404)
async def list_releases(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=_MAX_PAGE_SIZE)] = _DEFAULT_PAGE_SIZE,
    environment: _OptionalEnvironmentQuery = None,
) -> Page[ReleaseItem]:
    """Every release of a project, newest first — one entry per environment a scan was deployed to,
    so an environment's current release is its first entry."""
    await check_project_access(project_id, current_user, db)

    query: dict[str, Any] = {"project_id": project_id}
    if environment:
        query["environment"] = environment

    release_repo = ReleaseRepository(db)
    total = await release_repo.count(query)
    # The paged find breaks released_at ties on _id ascending, as RELEASES_LATEST_SORT does.
    rows = await release_repo.find_many_raw(
        query, skip=skip, limit=limit, sort_by="released_at", sort_order=pymongo.DESCENDING
    )
    return Page[ReleaseItem](items=await _to_items(db, rows), **page_meta(total, skip, limit))
