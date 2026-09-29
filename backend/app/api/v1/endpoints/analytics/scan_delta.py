"""Unified scan-delta endpoint dispatching across findings, components, and crypto."""

from typing import Literal

from fastapi import HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_400_403_404
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT, RELEASE_ENVIRONMENT_PATTERN
from app.repositories.scans import ScanRepository
from app.schemas.scan_delta import ScanDeltaResponse
from app.services.analytics.scan_delta import (
    InvalidDeltaQuery,
    compute_scan_delta_dispatch,
)
from app.services.releases import released_scan_ids, resolve_scan_ids

from ._shared import SCAN_NOT_IN_PROJECT

router = CustomAPIRouter()

_DeltaRef = Literal["release", "head"]

_REF_RELEASE: _DeltaRef = "release"
_REF_HEAD: _DeltaRef = "head"
_REF_DESCRIPTION = f'Resolve this side server-side: "{_REF_RELEASE}" or "{_REF_HEAD}"'
_ENVIRONMENT_DESCRIPTION = f'Environment whose release the "{_REF_RELEASE}" side resolves to'
_SIDE_FROM = "from"
_SIDE_TO = "to"


def _csv_to_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


async def _resolve_delta_ref(db: AsyncIOMotorDatabase, project_id: str, ref: _DeltaRef, environment: str) -> str | None:
    """Turn a symbolic side of the comparison into a scan id.

    The release side resolves through the rescan chain, so a delta compares the freshest analysis
    of the deployed artefact rather than what was known on the day it shipped.
    """
    release_environment = environment if ref == _REF_RELEASE else None
    return (await resolve_scan_ids(db, [project_id], release_environment=release_environment)).get(project_id)


async def _unresolved_ref_detail(db: AsyncIOMotorDatabase, project_id: str, ref: _DeltaRef, environment: str) -> str:
    """A marked release that resolves to nothing is retention or a broken rescan chain — an
    operational condition, unlike an environment nothing was ever released to."""
    if ref == _REF_HEAD:
        return f"{project_id} has no analysed {_REF_HEAD} scan"
    if environment in await released_scan_ids(db, project_id):
        return f"the {environment} release of {project_id} resolves to no analysed scan"
    return f"{project_id} has no analysed {_REF_RELEASE} scan in {environment}"


async def _resolve_side(
    db: AsyncIOMotorDatabase,
    project_id: str,
    side: str,
    scan_id: str | None,
    ref: _DeltaRef | None,
    environment: str,
) -> str:
    """One end of the comparison. A reference naming nothing is an absent record, so 404; an id and
    a reference for the same side contradict each other, so 400 rather than one silently winning."""
    if ref is None:
        if scan_id is None:
            raise HTTPException(status_code=400, detail=f"{side}_scan_id or {side} is required")
        return scan_id
    if scan_id is not None:
        raise HTTPException(status_code=400, detail=f"pass either {side}_scan_id or {side}, not both")

    resolved = await _resolve_delta_ref(db, project_id, ref, environment)
    if resolved is None:
        raise HTTPException(status_code=404, detail=await _unresolved_ref_detail(db, project_id, ref, environment))
    return resolved


@router.get("/scan-delta", responses=RESP_400_403_404)
async def get_scan_delta(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    project_id: str = Query(...),
    from_scan_id: str | None = Query(None),
    to_scan_id: str | None = Query(None),
    from_ref: _DeltaRef | None = Query(None, alias=_SIDE_FROM, description=_REF_DESCRIPTION),
    to_ref: _DeltaRef | None = Query(None, alias=_SIDE_TO, description=_REF_DESCRIPTION),
    release_environment: str | None = Query(
        None, pattern=RELEASE_ENVIRONMENT_PATTERN, description=_ENVIRONMENT_DESCRIPTION
    ),
    category: str = Query(...),  # str not enum: invalid values 400 via InvalidDeltaQuery, not 422
    page: int = Query(1),
    page_size: int = Query(50),
    change: str | None = Query(None),
    severity: str | None = Query(None, description="csv: critical,high,medium,low"),
    finding_type: str | None = Query(None, description="csv finding types"),
) -> ScanDeltaResponse:
    await check_project_access(project_id, current_user, db)

    if release_environment is not None and _REF_RELEASE not in (from_ref, to_ref):
        raise HTTPException(
            status_code=400,
            detail=f"release_environment is only valid with {_SIDE_FROM}={_REF_RELEASE} or {_SIDE_TO}={_REF_RELEASE}",
        )

    resolve_in = DEFAULT_RELEASE_ENVIRONMENT if release_environment is None else release_environment
    from_scan = await _resolve_side(db, project_id, _SIDE_FROM, from_scan_id, from_ref, resolve_in)
    to_scan = await _resolve_side(db, project_id, _SIDE_TO, to_scan_id, to_ref, resolve_in)

    if not await ScanRepository(db).belongs_to_project({from_scan, to_scan}, project_id):
        raise HTTPException(status_code=404, detail=SCAN_NOT_IN_PROJECT)

    try:
        return await compute_scan_delta_dispatch(
            db=db,
            project_id=project_id,
            category=category,
            from_scan=from_scan,
            to_scan=to_scan,
            page=page,
            page_size=page_size,
            change=change,
            severity=_csv_to_list(severity),
            finding_type=_csv_to_list(finding_type),
            allow_same_scan=(from_ref is not None or to_ref is not None),
        )
    except InvalidDeltaQuery as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
