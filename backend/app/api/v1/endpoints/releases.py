"""Mark, unmark and list the releases of a project."""

import logging
from datetime import datetime, timezone
from typing import Annotated, Any

import pymongo
from fastapi import HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep, ReleaseWriteDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404, RESP_AUTH_404_409
from app.core import ensure_utc
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT, PROJECT_ROLE_VIEWER, RELEASE_ENVIRONMENT_PATTERN
from app.core.init_db import RELEASES_LATEST_SORT
from app.models.release import Release
from app.repositories import ReleaseRepository
from app.schemas.release import ReleaseItem, ReleaseListResponse, ReleaseMarkRequest, ReleaseUnmarkResponse
from app.services.releases import effective_scan_ids

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

_SCAN_FIELDS = {"_id": 1, "commit_hash": 1, "branch": 1, "status": 1}
_DEFAULT_PAGE_SIZE = 20
_MAX_PAGE_SIZE = 100
_FIRST_PAGE = 1

_EnvironmentQuery = Annotated[str, Query(pattern=RELEASE_ENVIRONMENT_PATTERN)]
_OptionalEnvironmentQuery = Annotated[str | None, Query(pattern=RELEASE_ENVIRONMENT_PATTERN)]


def _to_item(row: dict[str, Any], scan: dict[str, Any], analysis_scan_id: str | None) -> ReleaseItem:
    return ReleaseItem(
        scan_id=row["scan_id"],
        project_id=row["project_id"],
        environment=row["environment"],
        version=row.get("version"),
        released_at=row["released_at"],
        commit_hash=scan.get("commit_hash"),
        branch=scan.get("branch"),
        scan_status=scan.get("status"),
        analysis_scan_id=analysis_scan_id,
    )


async def _to_items(db: AsyncIOMotorDatabase, rows: list[dict[str, Any]]) -> list[ReleaseItem]:
    if not rows:
        return []
    scan_ids = {row["scan_id"] for row in rows}
    scans = {doc["_id"]: doc async for doc in db.scans.find({"_id": {"$in": list(scan_ids)}}, _SCAN_FIELDS)}
    # The resolver's own chain walk, so a release names the scan analytics actually reports.
    analysis = await effective_scan_ids(db, scan_ids)
    return [_to_item(row, scans.get(row["scan_id"], {}), analysis.get(row["scan_id"])) for row in rows]


@router.post(
    "/{project_id}/releases",
    summary="Mark a commit's scan as released",
    status_code=201,
    responses=RESP_AUTH_404_409,
)
async def mark_release(
    project_id: ReleaseWriteDep,
    payload: ReleaseMarkRequest,
    db: DatabaseDep,
) -> ReleaseItem:
    """Mark the newest build scan of a commit as running in an environment.

    The CD stage knows the commit it deployed, not our scan id, and may deploy before analysis
    finishes — a mark states where an artefact runs, not what we know about it. Re-scans are excluded
    because they copy the commit verbatim with a fresh created_at, so re-marking an already-rescanned
    commit would otherwise resolve to a different scan and open a second record for one deployment.
    Re-marking is the rollback path: the older scan's own record wins on a fresher released_at.
    """
    scan = await db.scans.find_one(
        {
            "project_id": project_id,
            "commit_hash": payload.commit_hash,
            "is_rescan": {"$ne": True},
        },
        sort=[("created_at", pymongo.DESCENDING)],
    )
    if not scan:
        raise HTTPException(status_code=404, detail=f"No scan found for commit {payload.commit_hash}")

    scan_id = str(scan["_id"])
    environment = payload.environment or DEFAULT_RELEASE_ENVIRONMENT
    released_at = ensure_utc(payload.released_at) or datetime.now(timezone.utc)

    await ReleaseRepository(db).record(
        Release(
            project_id=project_id,
            environment=environment,
            # A CI producer sends an unset tag as "", and ReleaseRepository.record only skips a
            # None version, so an empty one would be stored as the release's name.
            version=payload.version or scan.get("commit_tag") or None,
            scan_id=scan_id,
            released_at=released_at,
        )
    )
    await db.scans.update_one({"_id": scan_id}, {"$set": {"is_release": True}})
    logger.info(
        "release.mark",
        extra={"project_id": project_id, "scan_id": scan_id, "environment": environment},
    )

    # Read back rather than echo: an unversioned re-mark keeps the version the deploy job recorded,
    # and that fallback belongs to the repository alone.
    row = await db.releases.find_one({"project_id": project_id, "environment": environment, "scan_id": scan_id})
    if row is None:
        raise HTTPException(status_code=409, detail=f"The release of {scan_id} to {environment} was withdrawn")
    return _to_item(row, scan, (await effective_scan_ids(db, [scan_id])).get(scan_id))


@router.delete(
    "/{project_id}/scans/{scan_id}/release",
    summary="Withdraw a scan from an environment",
    responses=RESP_AUTH_404,
)
async def unmark_release(
    project_id: ReleaseWriteDep,
    scan_id: str,
    db: DatabaseDep,
    environment: _EnvironmentQuery = DEFAULT_RELEASE_ENVIRONMENT,
) -> ReleaseUnmarkResponse:
    """Remove one environment's release record, the inverse of a mark of the same environment."""
    key = {"project_id": project_id, "environment": environment, "scan_id": scan_id}
    if (await db.releases.delete_one(key)).deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} is not released to {environment}")

    scan_key = {"project_id": project_id, "scan_id": scan_id}
    remaining: list[str] = sorted(await db.releases.distinct("environment", scan_key))
    # is_release denormalises "this scan has a release record" for the scans_released_list partial
    # index, so it is recomputed rather than cleared: a scan still released to another environment
    # has to stay indexed. Ingest never demotes; this is the only path that does.
    if not remaining:
        await db.scans.update_one({"_id": scan_id, "project_id": project_id}, {"$set": {"is_release": False}})

    # Marks are history, so withdrawing the newest uncovers the one below it and the environment
    # goes on reporting a release the operator did not choose. Read it back and say which.
    uncovered = await db.releases.find_one(
        {"project_id": project_id, "environment": environment}, sort=RELEASES_LATEST_SORT
    )
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
) -> ReleaseListResponse:
    """Every release of a project, newest first — one entry per environment a scan was deployed to,
    so an environment's current release is its first entry."""
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_VIEWER)

    query: dict[str, Any] = {"project_id": project_id}
    if environment:
        query["environment"] = environment

    total = await db.releases.count_documents(query)
    # _id breaks released_at ties: a CD job that marks two environments with one explicit timestamp
    # would otherwise leave "the latest release" to Mongo's unspecified order among equal keys.
    rows = await db.releases.find(
        query,
        sort=RELEASES_LATEST_SORT,
        skip=skip,
        limit=limit,
    ).to_list(limit)

    return ReleaseListResponse(
        items=await _to_items(db, rows),
        total=total,
        page=(skip // limit) + _FIRST_PAGE,
        size=limit,
    )
