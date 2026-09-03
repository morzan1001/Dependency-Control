"""Unified scan-delta endpoint dispatching across findings, components, and crypto."""

from fastapi import HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.analytics import ReleaseEnvironmentQuery
from app.api.v1.helpers.responses import RESP_400_403_404
from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT
from app.schemas.scan_delta import ScanDeltaResponse
from app.services.analytics.scan_delta import (
    InvalidDeltaQuery,
    compute_scan_delta_dispatch,
)
from app.services.analytics.scopes import ScopeResolver
from app.services.releases import latest_release_scan, resolve_scan_ids

router = CustomAPIRouter()

_REF_RELEASE = "release"
_REF_HEAD = "head"
_REF_DESCRIPTION = f'Resolve this side server-side: "{_REF_RELEASE}" or "{_REF_HEAD}"'
_SIDE_FROM = "from"
_SIDE_TO = "to"


def _csv_to_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


async def _resolve_delta_ref(
    db: AsyncIOMotorDatabase, project_id: str, ref: str, environment: str
) -> str | None:
    """Turn a symbolic side of the comparison into a scan id.

    The release side resolves through the rescan chain, so a delta compares the freshest analysis
    of the deployed artefact rather than what was known on the day it shipped.
    """
    if ref == _REF_RELEASE:
        return await latest_release_scan(db, project_id, environment)
    if ref == _REF_HEAD:
        return (await resolve_scan_ids(db, [project_id])).get(project_id)
    raise HTTPException(status_code=400, detail=f"unknown scan reference: {ref}")


async def _resolve_side(
    db: AsyncIOMotorDatabase,
    project_id: str,
    side: str,
    scan_id: str | None,
    ref: str | None,
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
        located = f" in {environment}" if ref == _REF_RELEASE else ""
        raise HTTPException(status_code=404, detail=f"{project_id} has no analysed {ref} scan{located}")
    return resolved


@router.get("/scan-delta", response_model=ScanDeltaResponse, responses=RESP_400_403_404)
async def get_scan_delta(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    project_id: str = Query(...),
    from_scan_id: str | None = Query(None),
    to_scan_id: str | None = Query(None),
    from_ref: str | None = Query(None, alias=_SIDE_FROM, description=_REF_DESCRIPTION),
    to_ref: str | None = Query(None, alias=_SIDE_TO, description=_REF_DESCRIPTION),
    environment: ReleaseEnvironmentQuery = None,
    category: str = Query(...),  # str not enum: invalid values 400 via InvalidDeltaQuery, not 422
    page: int = Query(1),
    page_size: int = Query(50),
    change: str | None = Query(None),
    severity: str | None = Query(None, description="csv: critical,high,medium,low"),
    finding_type: str | None = Query(None, description="csv finding types"),
) -> ScanDeltaResponse:
    await ScopeResolver(db, current_user).resolve(
        scope="project",
        scope_id=project_id,
    )

    resolve_in = DEFAULT_RELEASE_ENVIRONMENT if environment is None else environment
    from_scan = await _resolve_side(db, project_id, _SIDE_FROM, from_scan_id, from_ref, resolve_in)
    to_scan = await _resolve_side(db, project_id, _SIDE_TO, to_scan_id, to_ref, resolve_in)

    # Both scans must belong to project_id; runs after auth to avoid leaking
    # scan existence to non-members.
    if from_scan != to_scan:
        found = await db["scans"].count_documents(
            {"_id": {"$in": [from_scan, to_scan]}, "project_id": project_id},
        )
        if found != 2:
            raise HTTPException(status_code=400, detail="scan not in project")

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
        )
    except InvalidDeltaQuery as e:
        raise HTTPException(status_code=400, detail=str(e))
