"""HTTP contract and job-document transitions for compliance report lifecycle endpoints."""

import pytest


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
    assert len(resp.json()["reports"]) == 2


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
    assert dele.status_code == 204
    followup = await client.get(
        f"/api/v1/compliance/reports/{report_id}",
        headers=owner_auth_headers_proj,
    )
    assert followup.status_code == 404
