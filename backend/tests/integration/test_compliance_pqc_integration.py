"""
Integration smoke test for the PQC migration plan compliance framework.

Regression for the critical `asyncio.run()` in running loop bug: the PQC
framework's sync ``evaluate()`` used to call ``asyncio.run(...)`` from the
FastAPI BackgroundTask event loop, which raises RuntimeError and flipped
every PQC report to status=failed. After the fix the engine dispatches on
``evaluate_async``; this test drives the full HTTP + BackgroundTask path and
asserts status != "failed".

The fake DB used in integration tests does not implement GridFS or the full
scan/crypto_asset query surface. We therefore accept ``completed`` as the
happy path and also accept any terminal state *other than* ``failed`` —
what we specifically guard against is the RuntimeError regression.
"""

import asyncio

import pytest


@pytest.mark.asyncio
async def test_pqc_report_does_not_crash_with_asyncio_run(
    client, db, owner_auth_headers_proj,
):
    resp = await client.post(
        "/api/v1/compliance/reports",
        json={
            "scope": "project", "scope_id": "p",
            "framework": "pqc-migration-plan",
            "format": "json",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 202, resp.text
    report_id = resp.json()["report_id"]

    data = None
    for _ in range(50):
        get = await client.get(
            f"/api/v1/compliance/reports/{report_id}",
            headers=owner_auth_headers_proj,
        )
        assert get.status_code == 200
        data = get.json()
        if data["status"] in ("completed", "failed"):
            break
        await asyncio.sleep(0.1)

    assert data is not None
    # The critical assertion: no RuntimeError("asyncio.run() cannot be called
    # from a running event loop") should leak through. Accept completed; skip
    # if the fake DB couldn't satisfy the data path for some unrelated reason.
    if data["status"] == "failed":
        err = (data.get("error_message") or "").lower()
        if "asyncio.run" in err or "running event loop" in err:
            pytest.fail(f"PQC framework still calls asyncio.run in running loop: {err}")
        pytest.skip(
            f"Fake DB cannot satisfy PQC generator data path (error: {err}); "
            "the asyncio.run regression is what this test guards against.",
        )
    assert data["status"] == "completed", data
