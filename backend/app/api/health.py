from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from app.db.mongodb import db
from app.core.worker import worker_manager

router = APIRouter()

@router.get("/live", summary="Liveness Probe")
async def liveness():
    """
    Simple liveness probe to check if the application process is running.
    """
    return {"status": "alive"}

@router.get("/ready", summary="Readiness Probe")
async def readiness():
    """
    Detailed readiness probe.
    Checks:
    1. MongoDB connectivity (ping)
    2. Worker status (are background tasks running?)
    """
    components = {
        "database": "unknown",
        "workers": "unknown"
    }
    is_ready = True

    # 1. Check MongoDB
    try:
        if db.client:
            # The 'ping' command is cheap and effective
            await db.client.admin.command('ping')
            components["database"] = "connected"
        else:
            components["database"] = "client_not_initialized"
            is_ready = False
    except Exception as e:
        components["database"] = f"error: {str(e)}"
        is_ready = False

    # 2. Check Workers
    # We check if we have workers and if at least one is running (not cancelled/done)
    active_workers = [t for t in worker_manager.workers if not t.done()]
    if active_workers:
        components["workers"] = f"operational ({len(active_workers)}/{worker_manager.num_workers} active)"
    else:
        # If workers are supposed to be running but aren't, that's an issue for full system readiness
        # However, for API readiness (serving read requests), it might be fine.
        # But user asked for "detailed status" and "problems in service".
        # If workers are dead, ingestion won't work.
        components["workers"] = "stopped"
        # We might not want to fail readiness just because workers are down if we want to allow read-only API access.
        # But usually for a monolithic pod, if part is broken, we restart or don't send traffic.
        # Let's mark it as not ready if workers are completely dead to be safe.
        if worker_manager.num_workers > 0:
             is_ready = False

    if is_ready:
        return {"status": "ready", "components": components}
    else:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "components": components}
        )
