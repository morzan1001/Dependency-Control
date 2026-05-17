"""
REST endpoints for crypto analytics (hotspots, trends).
"""

from datetime import datetime
from typing import Literal, Optional

from fastapi import HTTPException, Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_400_403, RESP_403, RESP_404
from app.schemas.analytics import HotspotResponse, TrendSeries
from app.services.analytics.crypto_hotspots import CryptoHotspotService, GroupBy
from app.services.analytics.crypto_trends import Bucket, CryptoTrendService, Metric
from app.services.analytics.scopes import (
    ScopeResolutionError,
    ScopeResolver,
)

_ScopeLit = Literal["project", "team", "global", "user"]

router = CustomAPIRouter(prefix="/analytics/crypto", tags=["crypto-analytics"])

_SCOPE_PATTERN = "^(project|team|global|user)$"


@router.get("/hotspots", response_model=HotspotResponse, responses=RESP_403)
async def get_hotspots(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scope: _ScopeLit = Query(..., pattern=_SCOPE_PATTERN),
    scope_id: Optional[str] = Query(None),
    group_by: GroupBy = Query("name"),
    scan_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
) -> HotspotResponse:
    try:
        resolved = await ScopeResolver(db, current_user).resolve(
            scope=scope,
            scope_id=scope_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return await CryptoHotspotService(db).hotspots(
        resolved=resolved,
        group_by=group_by,
        scan_id=scan_id,
        limit=limit,
    )


@router.get("/hotspots/{key}/locations", responses={**RESP_403, **RESP_404})
async def get_hotspot_locations(
    key: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scope: _ScopeLit = Query(..., pattern=_SCOPE_PATTERN),
    scope_id: Optional[str] = Query(None),
    grouping: GroupBy = Query("name"),
) -> object:
    try:
        resolved = await ScopeResolver(db, current_user).resolve(
            scope=scope,
            scope_id=scope_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    resp = await CryptoHotspotService(db).hotspots(
        resolved=resolved,
        group_by=grouping,
        limit=500,
    )
    matches = [e for e in resp.items if e.key == key]
    if not matches:
        raise HTTPException(status_code=404, detail="hotspot not found")
    return matches[0]


@router.get("/trends", response_model=TrendSeries, responses=RESP_400_403)
async def get_trends(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    range_start: datetime = Query(...),
    range_end: datetime = Query(...),
    scope: _ScopeLit = Query(..., pattern=_SCOPE_PATTERN),
    scope_id: Optional[str] = Query(None),
    metric: Metric = Query("total_crypto_findings"),
    bucket: Bucket = Query("week"),
) -> TrendSeries:
    try:
        resolved = await ScopeResolver(db, current_user).resolve(
            scope=scope,
            scope_id=scope_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    try:
        return await CryptoTrendService(db).trend(
            resolved=resolved,
            metric=metric,
            bucket=bucket,
            range_start=range_start,
            range_end=range_end,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
