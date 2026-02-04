import gc
import os
import sys
from collections import Counter
from typing import Any, Dict

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.cache import cache_service
from app.core.worker import worker_manager
from app.db.mongodb import db

router = APIRouter()


@router.get("/live", summary="Liveness Probe")
async def liveness():
    """
    Liveness probe to check if the application process is running.
    Uses JSONResponse directly to bypass Pydantic validation overhead.
    """
    return JSONResponse(content={"status": "alive"})


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
        return JSONResponse(content={"status": "ready", "components": components})

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


@router.get("/debug/memory", summary="Memory Debug Info", include_in_schema=False)
async def memory_debug() -> Dict[str, Any]:
    """
    Debug endpoint to analyze memory usage of the running process.
    Only accessible internally, not exposed via ingress.
    """
    # Force garbage collection first
    gc.collect()

    # Get memory info from /proc
    memory_info = {}
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith(("VmRSS", "VmSize", "VmPeak", "VmData", "VmStk")):
                    key, value = line.split(":", 1)
                    memory_info[key.strip()] = value.strip()
    except Exception:
        pass

    # Count Python objects by type
    all_objects = gc.get_objects()
    type_counts = Counter(type(obj).__name__ for obj in all_objects)
    top_types = dict(type_counts.most_common(30))

    # Check for large containers and identify them
    large_dicts = []
    large_lists = []
    for obj in all_objects:
        if isinstance(obj, dict) and len(obj) > 1000:
            # Try to identify what this dict is
            sample_keys = list(obj.keys())[:5]
            large_dicts.append({
                "size": len(obj),
                "sample_keys": [str(k)[:50] for k in sample_keys],
            })
        elif isinstance(obj, list) and len(obj) > 1000:
            # Try to identify what types are in this list
            type_sample = [type(x).__name__ for x in obj[:5]]
            large_lists.append({
                "size": len(obj),
                "type_sample": type_sample,
            })

    # GC stats
    gc_stats = {
        "collections": gc.get_count(),
        "thresholds": gc.get_threshold(),
        "garbage_count": len(gc.garbage),
    }

    return {
        "process_memory": memory_info,
        "python_objects": {
            "total_count": len(all_objects),
            "top_types": top_types,
            "large_dicts": large_dicts,
            "large_lists": large_lists,
        },
        "gc_stats": gc_stats,
        "modules_loaded": len(sys.modules),
    }
