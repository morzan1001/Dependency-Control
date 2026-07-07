import time
from typing import Any, Dict

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.cache import cache_service
from app.core.config import settings
from app.core.worker import worker_manager
from app.db.mongodb import db

router = APIRouter()

_startup_time = time.time()


def get_uptime_seconds() -> float:
    return time.time() - _startup_time


def get_max_uptime_seconds() -> int:
    """Max uptime before the pod should restart; 0 disables."""
    return getattr(settings, "MAX_POD_UPTIME_SECONDS", 86400)


@router.get("/live", summary="Liveness Probe", response_model=None)
async def liveness() -> Dict[str, Any] | JSONResponse:
    """Liveness probe; reports unhealthy past max uptime to recycle pods for memory."""
    uptime = get_uptime_seconds()
    max_uptime = get_max_uptime_seconds()

    if max_uptime > 0 and uptime > max_uptime:
        uptime_hours = uptime / 3600
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "restart_required",
                "uptime_hours": round(uptime_hours, 2),
                "max_uptime_hours": max_uptime / 3600,
                "reason": "Pod has exceeded maximum uptime and will be restarted",
            },
        )

    return {"status": "alive", "uptime_seconds": int(uptime)}


@router.get("/ready", summary="Readiness Probe", response_model=None)
async def readiness() -> Dict[str, Any] | JSONResponse:
    """Readiness probe checking MongoDB, workers, and (optional) Redis cache."""
    components = {"database": "unknown", "workers": "unknown", "cache": "unknown"}
    is_ready = True

    try:
        if db.client:
            await db.client.admin.command("ping")
            components["database"] = "connected"
        else:
            components["database"] = "client_not_initialized"
            is_ready = False
    except Exception as e:
        components["database"] = f"error: {str(e)}"
        is_ready = False

    active_workers = [t for t in worker_manager.workers if not t.done()]
    if active_workers:
        components["workers"] = f"operational ({len(active_workers)}/{worker_manager.num_workers} active)"
    else:
        components["workers"] = "stopped"
        # Fail readiness only if workers are configured but all are dead.
        if worker_manager.num_workers > 0:
            is_ready = False

    # Cache is optional; its failure degrades but does not fail readiness.
    try:
        cache_health = await cache_service.health_check()
        if cache_health.get("status") == "healthy":
            components["cache"] = "connected"
        else:
            components["cache"] = "unavailable (degraded mode)"
    except Exception as e:
        components["cache"] = f"unavailable: {str(e)}"

    if is_ready:
        return {"status": "ready", "components": components}

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "not_ready", "components": components},
    )


@router.get("/cache", summary="Cache Health & Statistics")
async def cache_health() -> Dict[str, Any]:
    """Cache health status and statistics."""
    try:
        health = await cache_service.health_check()
        return health
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "available": False,
        }
