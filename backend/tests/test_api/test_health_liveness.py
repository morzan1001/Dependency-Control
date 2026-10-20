import asyncio
import json
import time

import pytest
from prometheus_client import REGISTRY

from app.api import health
from app.core import metrics


@pytest.mark.parametrize(
    ("max_uptime", "uptime", "status_code"),
    [(100, 50, None), (100, 150, 503), (0, 10**9, None)],
)
def test_liveness_recycles_past_max_pod_uptime(monkeypatch, max_uptime, uptime, status_code):
    monkeypatch.setattr(health.settings, "MAX_POD_UPTIME_SECONDS", max_uptime)
    monkeypatch.setattr(health, "process_uptime_seconds", lambda: uptime)

    response = asyncio.run(health.liveness())

    if status_code is None:
        assert response == {"status": "alive", "uptime_seconds": uptime}
    else:
        assert response.status_code == status_code


def test_liveness_reads_the_clock_the_uptime_gauge_reads(monkeypatch):
    monkeypatch.setattr(metrics, "startup_time", time.time() - 1000)
    monkeypatch.setattr(health.settings, "MAX_POD_UPTIME_SECONDS", 0)

    response = asyncio.run(health.liveness())
    metrics.update_uptime()

    assert response["uptime_seconds"] == pytest.approx(REGISTRY.get_sample_value("uptime_seconds"), abs=1)


@pytest.mark.parametrize(
    ("cache_status", "component"),
    [("healthy", "connected"), ("unhealthy", "unavailable (degraded mode)")],
)
def test_readiness_reports_the_cache_without_depending_on_it(monkeypatch, cache_status, component):
    async def health_check():
        return {"status": cache_status}

    monkeypatch.setattr(health.cache_service, "health_check", health_check)
    monkeypatch.setattr(health.db, "client", None)

    response = asyncio.run(health.readiness())

    assert response.status_code == 503
    assert json.loads(response.body)["components"]["cache"] == component
