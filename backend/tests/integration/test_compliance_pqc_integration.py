"""A PQC migration-plan report completes over the HTTP + BackgroundTask path without failing on an asyncio.run-in-running-loop error."""

import asyncio

import pytest

_POLL_ATTEMPTS = 50
_POLL_INTERVAL_SECONDS = 0.1
_TERMINAL_STATUSES = ("completed", "failed")


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_pqc_report_does_not_crash_with_asyncio_run(
    client,
    db,
    owner_auth_headers_proj,
):
    resp = await client.post(
        "/api/v1/compliance/reports",
        json={
            "scope": "project",
            "scope_id": "p",
            "framework": "pqc-migration-plan",
            "format": "json",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 202, resp.text
    report_id = resp.json()["report_id"]

    data = {}
    for _ in range(_POLL_ATTEMPTS):
        get = await client.get(
            f"/api/v1/compliance/reports/{report_id}",
            headers=owner_auth_headers_proj,
        )
        assert get.status_code == 200
        data = get.json()
        if data["status"] in _TERMINAL_STATUSES:
            break
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    assert data["status"] == "completed", data
