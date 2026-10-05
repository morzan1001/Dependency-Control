"""PQC migration plan REST endpoint."""

from fastapi import Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_active_user, get_database
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_403
from app.core.constants import (
    DEFAULT_PQC_PLAN_ITEMS,
    MAX_PQC_PLAN_ITEMS,
    ScopeName,
)
from app.models.user import User
from app.schemas.pqc_migration import MigrationPlanResponse
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ScopeResolver
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator
from app.services.pqc_migration.mappings_loader import CURRENT_MAPPINGS_VERSION

router = CustomAPIRouter(prefix="/analytics/crypto", tags=["pqc-migration"])


@router.get("/pqc-migration", responses=RESP_403)
async def get_pqc_migration_plan(
    scope: ScopeName = Query(...),
    scope_id: str | None = Query(None),
    limit: int = Query(DEFAULT_PQC_PLAN_ITEMS, ge=1, le=MAX_PQC_PLAN_ITEMS),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> MigrationPlanResponse:
    resolved = await ScopeResolver(db, current_user).resolve(
        scope=scope,
        scope_id=scope_id,
    )

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
    if hit and isinstance(cached, MigrationPlanResponse):
        return cached

    resp = await PQCMigrationPlanGenerator(db).generate(
        resolved=resolved,
        limit=limit,
    )
    cache.set(cache_key, resp)
    return resp
