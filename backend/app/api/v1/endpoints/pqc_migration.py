"""PQC migration plan REST endpoint."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_current_active_user, get_database
from app.schemas.pqc_migration import MigrationPlanResponse
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ScopeResolutionError, ScopeResolver
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator
from app.services.pqc_migration.mappings_loader import CURRENT_MAPPINGS_VERSION

router = APIRouter(prefix="/analytics/crypto", tags=["pqc-migration"])


@router.get("/pqc-migration", response_model=MigrationPlanResponse)
async def get_pqc_migration_plan(
    scope: str = Query(..., pattern="^(project|team|global|user)$"),
    scope_id: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    current_user=Depends(get_current_active_user),
    db=Depends(get_database),
):
    try:
        resolved = await ScopeResolver(db, current_user).resolve(
            scope=scope,
            scope_id=scope_id,
        )
    except ScopeResolutionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    cache = get_analytics_cache()
    cache_key = (
        "pqc-migration",
        scope,
        scope_id,
        current_user.id,
        limit,
        CURRENT_MAPPINGS_VERSION,
    )
    hit, cached = cache.get(cache_key)
    if hit:
        return cached

    resp = await PQCMigrationPlanGenerator(db).generate(
        resolved=resolved,
        limit=limit,
    )
    cache.set(cache_key, resp)
    return resp
