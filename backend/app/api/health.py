from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.worker import worker_manager
from app.db.mongodb import db

router = APIRouter()


@router.get("/live", summary="Liveness Probe")
async def liveness():
    """
    Liveness probe to check if the application process is running.
    """
    return {"status": "alive"}


@router.get("/ready", summary="Readiness Probe")
async def readiness():
    """
    Detailed readiness probe.
    Checks:
    1. MongoDB connectivity (ping)
    2. Worker status (background tasks execution status)
    """
    components = {"database": "unknown", "workers": "unknown"}
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

    if is_ready:
        return {"status": "ready", "components": components}

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "not_ready", "components": components},
    )
