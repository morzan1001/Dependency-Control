import asyncio
import json

import pytest

from app.api import health


@pytest.mark.parametrize(
    ("max_uptime", "uptime", "status_code"),
    [(100, 50, None), (100, 150, 503), (0, 10**9, None)],
)
def test_liveness_recycles_past_max_pod_uptime(monkeypatch, max_uptime, uptime, status_code):
    monkeypatch.setattr(health.settings, "MAX_POD_UPTIME_SECONDS", max_uptime)
    monkeypatch.setattr(health, "get_uptime_seconds", lambda: uptime)

    response = asyncio.run(health.liveness())

    if status_code is None:
        assert response == {"status": "alive", "uptime_seconds": uptime}
    else:
        assert response.status_code == status_code


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
