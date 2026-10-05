import asyncio

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
