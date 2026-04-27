"""PQC migration plan REST endpoint."""

import logging
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import BackgroundTasks, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_active_user, get_database
from app.api.router import CustomAPIRouter
from app.core.constants import WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED
from app.models.user import User
from app.schemas.pqc_migration import MigrationPlanResponse
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.scopes import ResolvedScope, ScopeResolutionError, ScopeResolver
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator
from app.services.pqc_migration.mappings_loader import CURRENT_MAPPINGS_VERSION

logger = logging.getLogger(__name__)

router = CustomAPIRouter(prefix="/analytics/crypto", tags=["pqc-migration"])


@router.get("/pqc-migration", response_model=MigrationPlanResponse)
async def get_pqc_migration_plan(
    background_tasks: BackgroundTasks,
    scope: Literal["project", "team", "global", "user"] = Query(..., pattern="^(project|team|global|user)$"),
    scope_id: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    current_user: User = Depends(get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> MigrationPlanResponse:
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
    if hit and isinstance(cached, MigrationPlanResponse):
        return cached

    resp = await PQCMigrationPlanGenerator(db).generate(
        resolved=resolved,
        limit=limit,
    )
    cache.set(cache_key, resp)

    # Fire webhook out-of-band so a slow webhook endpoint cannot block the
    # API response. Failures are swallowed inside `_fire_pqc_webhook`.
    background_tasks.add_task(_fire_pqc_webhook, db, resp, resolved)

    return resp


async def _fire_pqc_webhook(
    db: AsyncIOMotorDatabase,
    resp: MigrationPlanResponse,
    resolved: ResolvedScope,
) -> None:
    """Best-effort webhook dispatch for the PQC migration plan.

    Modeled after ``compliance_reports._run_and_webhook`` — any exception is
    logged but never re-raised, because the plan has already been delivered
    to the caller by the time this background task runs.
    """
    from app.services.webhooks import webhook_service

    payload = {
        "event": WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scope": resolved.scope,
        "scope_id": resolved.scope_id,
        "total_items": resp.summary.total_items,
        "status_counts": resp.summary.status_counts,
        "mappings_version": resp.mappings_version,
    }
    await webhook_service.safe_trigger_webhooks(
        db,
        event_type=WEBHOOK_EVENT_PQC_MIGRATION_PLAN_GENERATED,
        payload=payload,
        project_id=resolved.scope_id if resolved.scope == "project" else None,
        context="pqc_migration",
    )
