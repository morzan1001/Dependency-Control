"""
REST endpoints for crypto analytics (hotspots, trends, scan-delta).
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.schemas.analytics import HotspotResponse, ScanDelta, TrendSeries
from app.services.analytics.crypto_delta import compute_scan_delta
from app.services.analytics.crypto_hotspots import CryptoHotspotService, GroupBy
from app.services.analytics.crypto_trends import Bucket, CryptoTrendService, Metric
from app.services.analytics.scopes import (
    ScopeResolutionError,
    ScopeResolver,
)

router = APIRouter(prefix="/analytics/crypto", tags=["crypto-analytics"])


@router.get("/hotspots", response_model=HotspotResponse)
async def get_hotspots(
    scope: str = Query(..., pattern="^(project|team|global)$"),
    scope_id: Optional[str] = Query(None),
    group_by: GroupBy = Query("name"),
    scan_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    current_user: CurrentUserDep = None,
    db: DatabaseDep = None,
):
    try:
        resolved = await ScopeResolver(db, current_user).resolve(
            scope=scope, scope_id=scope_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return await CryptoHotspotService(db).hotspots(
        resolved=resolved, group_by=group_by, scan_id=scan_id, limit=limit,
    )


@router.get("/hotspots/{key}/locations")
async def get_hotspot_locations(
    key: str,
    scope: str = Query(..., pattern="^(project|team|global)$"),
    scope_id: Optional[str] = Query(None),
    grouping: GroupBy = Query("name"),
    current_user: CurrentUserDep = None,
    db: DatabaseDep = None,
):
    try:
        resolved = await ScopeResolver(db, current_user).resolve(
            scope=scope, scope_id=scope_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    resp = await CryptoHotspotService(db).hotspots(
        resolved=resolved, group_by=grouping, limit=500,
    )
    matches = [e for e in resp.items if e.key == key]
    if not matches:
        raise HTTPException(status_code=404, detail="hotspot not found")
    return matches[0]


@router.get("/trends", response_model=TrendSeries)
async def get_trends(
    scope: str = Query(..., pattern="^(project|team|global)$"),
    scope_id: Optional[str] = Query(None),
    metric: Metric = Query("total_crypto_findings"),
    bucket: Bucket = Query("week"),
    range_start: datetime = Query(...),
    range_end: datetime = Query(...),
    current_user: CurrentUserDep = None,
    db: DatabaseDep = None,
):
    try:
        resolved = await ScopeResolver(db, current_user).resolve(
            scope=scope, scope_id=scope_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    try:
        return await CryptoTrendService(db).trend(
            resolved=resolved, metric=metric, bucket=bucket,
            range_start=range_start, range_end=range_end,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/scan-delta", response_model=ScanDelta)
async def get_scan_delta(
    project_id: str = Query(...),
    from_scan: str = Query(..., alias="from"),
    to_scan: str = Query(..., alias="to"),
    current_user: CurrentUserDep = None,
    db: DatabaseDep = None,
):
    try:
        await ScopeResolver(db, current_user).resolve(
            scope="project", scope_id=project_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return await compute_scan_delta(
        db, project_id, from_scan=from_scan, to_scan=to_scan,
    )
