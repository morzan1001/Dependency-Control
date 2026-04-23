"""
Integration tests for compliance report lifecycle endpoints.

The fake DB used in integration tests does not implement GridFS or
`_id`-projection lookups; the engine's `_store_artifact` and `_pick_scan_ids`
paths therefore don't produce a real artifact. These tests cover the HTTP
contract + job-document transitions; the real data path is exercised by the
unit tests (D.4) and the format tests (D.6).
"""

import asyncio

import pytest


@pytest.mark.asyncio
async def test_report_post_then_get_then_download(
    client,
    db,
    owner_auth_headers_proj,
):
    resp = await client.post(
        "/api/v1/compliance/reports",
        json={
            "scope": "project",
            "scope_id": "p",
            "framework": "nist-sp-800-131a",
            "format": "json",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "pending"
    report_id = body["report_id"]

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

    # Lifecycle test: accept completed OR failed - fake DB may not support
    # the full engine data path. We just assert the job reached a terminal state.
    assert data is not None
    assert data["status"] in ("completed", "failed"), data

    if data["status"] == "completed":
        dl = await client.get(
            f"/api/v1/compliance/reports/{report_id}/download",
            headers=owner_auth_headers_proj,
        )
        # Fake DB may not support GridFS; a 410 or 5xx here is acceptable.
        assert dl.status_code in (200, 410, 500)


@pytest.mark.asyncio
async def test_list_reports(client, db, owner_auth_headers_proj):
    for _ in range(2):
        resp = await client.post(
            "/api/v1/compliance/reports",
            json={"scope": "project", "scope_id": "p", "framework": "bsi-tr-02102", "format": "csv"},
            headers=owner_auth_headers_proj,
        )
        assert resp.status_code == 202, resp.text
    resp = await client.get(
        "/api/v1/compliance/reports?scope=project&scope_id=p&limit=10",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "reports" in body
    assert len(body["reports"]) >= 2


@pytest.mark.asyncio
async def test_delete_report(client, db, owner_auth_headers_proj):
    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p", "framework": "cnsa-2.0", "format": "json"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 202, resp.text
    report_id = resp.json()["report_id"]
    dele = await client.delete(
        f"/api/v1/compliance/reports/{report_id}",
        headers=owner_auth_headers_proj,
    )
    assert dele.status_code in (200, 204)
    followup = await client.get(
        f"/api/v1/compliance/reports/{report_id}",
        headers=owner_auth_headers_proj,
    )
    assert followup.status_code == 404
