import time

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.cache import cache_service
from app.core.config import settings
from app.core.worker import worker_manager
from app.db.mongodb import db

router = APIRouter()

# Track when the application started
_startup_time = time.time()


def get_uptime_seconds() -> float:
    """Get the application uptime in seconds."""
    return time.time() - _startup_time


def get_max_uptime_seconds() -> int:
    """
    Get the maximum allowed uptime before the pod should restart.
    Default: 24 hours (86400 seconds). Set to 0 to disable.
    """
    return getattr(settings, "MAX_POD_UPTIME_SECONDS", 86400)


@router.get("/live", summary="Liveness Probe")
async def liveness():
    """
    Liveness probe to check if the application process is running.

    Returns unhealthy after MAX_POD_UPTIME_SECONDS to trigger a graceful restart.
    This helps manage memory growth by ensuring pods are periodically recycled.
    The PodDisruptionBudget ensures pods restart one at a time.
    """
    uptime = get_uptime_seconds()
    max_uptime = get_max_uptime_seconds()

    # Check if we've exceeded the max uptime (0 = disabled)
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


@router.get("/ready", summary="Readiness Probe")
async def readiness():
    """
    Detailed readiness probe.
    Checks:
    1. MongoDB connectivity (ping)
    2. Worker status (background tasks execution status)
    3. Redis cache availability (optional - service can run without it)
    """
    components = {"database": "unknown", "workers": "unknown", "cache": "unknown"}
    is_ready = True

    # 1. Check MongoDB
    try:
        if db.client:
            # The 'ping' command is cheap and effective
            await db.client.admin.command("ping")
            components["database"] = "connected"
        else:
            components["database"] = "client_not_initialized"
            is_ready = False
    except Exception as e:
        components["database"] = f"error: {str(e)}"
        is_ready = False

    # 2. Check Workers
    # Checks if workers are configured and if at least one is running (not cancelled/done)
    active_workers = [t for t in worker_manager.workers if not t.done()]
    if active_workers:
        components["workers"] = (
            f"operational ({len(active_workers)}/{worker_manager.num_workers} active)"
        )
    else:
        components["workers"] = "no_active_workers"
        # The service is considered degraded but not necessarily down if workers are missing,
        # as the API can still serve read requests.
        # However, for strict readiness, returning 503 might be appropriate.
        # Currently, this is just reported.
        # If workers are dead, ingestion won't work.
        components["workers"] = "stopped"
        # Failing readiness might not be desired just because workers are down if read-only API access is allowed.
        # Usually for a monolithic pod, if part is broken, it is restarted or traffic is not sent.
        # Let's mark it as not ready if workers are completely dead to be safe.
        if worker_manager.num_workers > 0:
            is_ready = False

    # 3. Check Redis Cache (optional - degraded but functional without it)
    try:
        cache_health = await cache_service.health_check()
        if cache_health.get("status") == "healthy":
            components["cache"] = "connected"
        else:
            components["cache"] = "unavailable (degraded mode)"
            # Cache is optional - don't fail readiness
    except Exception as e:
        components["cache"] = f"unavailable: {str(e)}"
        # Cache is optional - service can run without it

    if is_ready:
        return {"status": "ready", "components": components}

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "not_ready", "components": components},
    )


@router.get("/cache", summary="Cache Health & Statistics")
async def cache_health():
    """
    Get detailed cache health status and statistics.

    Returns:
        Cache connection status, memory usage, key count, and hit rate.
    """
    try:
        health = await cache_service.health_check()
        return health
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "available": False,
        }
