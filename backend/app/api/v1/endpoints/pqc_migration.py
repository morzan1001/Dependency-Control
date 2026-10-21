from fastapi import Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_403, RESP_413
from app.core.constants import (
    DEFAULT_PQC_PLAN_ITEMS,
    MAX_PQC_PLAN_ITEMS,
    ScopeName,
)
from app.schemas.pqc_migration import MigrationPlanResponse
from app.services.analytics.scopes import ScopeResolver
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator

router = CustomAPIRouter(prefix="/analytics/crypto", tags=["pqc-migration"], responses=RESP_413)


@router.get("/pqc-migration", responses=RESP_403)
async def get_pqc_migration_plan(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scope: ScopeName = Query(...),
    scope_id: str | None = Query(None),
    limit: int = Query(DEFAULT_PQC_PLAN_ITEMS, ge=1, le=MAX_PQC_PLAN_ITEMS),
) -> MigrationPlanResponse:
    resolved = await ScopeResolver(db, current_user).resolve(
        scope=scope,
        scope_id=scope_id,
    )
    return await PQCMigrationPlanGenerator(db).plan(resolved=resolved, limit=limit)
