"""
Integration tests for the unified scan-delta REST endpoint.

GET /api/v1/analytics/scan-delta covers findings, components, and crypto
deltas under a single envelope. These tests verify the endpoint layer:
project authorization, cross-project scan guards, and InvalidDeltaQuery
mapping to HTTP 400.
"""

from datetime import datetime, timezone

import pytest


BASE = "/api/v1/analytics/scan-delta"


def _scan_doc(scan_id: str, project_id: str) -> dict:
    return {
        "_id": scan_id,
        "project_id": project_id,
        "status": "completed",
        "created_at": datetime.now(timezone.utc),
    }


@pytest.mark.asyncio
async def test_returns_403_for_non_member(client, db, owner_auth_headers_proj_p2):
    """User who is a member of project p2 must NOT see scan-delta for project p."""
    await db["scans"].insert_one(_scan_doc("s1", "p"))
    await db["scans"].insert_one(_scan_doc("s2", "p"))

    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "s1",
            "to_scan_id": "s2",
            "category": "findings",
        },
        headers=owner_auth_headers_proj_p2,
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_returns_400_when_scan_not_in_project(client, db, owner_auth_headers_proj):
    """If either scan belongs to another project, return 400."""
    await db["scans"].insert_one(_scan_doc("in1", "p"))
    await db["scans"].insert_one(_scan_doc("out1", "p_other"))

    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "in1",
            "to_scan_id": "out1",
            "category": "findings",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 400, resp.text
    assert "not in project" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_returns_400_for_identical_scan_ids(client, owner_auth_headers_proj):
    """from_scan_id == to_scan_id is rejected by the orchestrator."""
    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "x",
            "to_scan_id": "x",
            "category": "findings",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
async def test_returns_400_for_unknown_category(client, db, owner_auth_headers_proj):
    """Unknown category value should surface as 400 (not 422) per spec."""
    await db["scans"].insert_one(_scan_doc("u1", "p"))
    await db["scans"].insert_one(_scan_doc("u2", "p"))

    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "u1",
            "to_scan_id": "u2",
            "category": "bogus",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
async def test_returns_400_for_severity_with_components(client, db, owner_auth_headers_proj):
    """severity filter is only valid with category=findings."""
    await db["scans"].insert_one(_scan_doc("c1", "p"))
    await db["scans"].insert_one(_scan_doc("c2", "p"))

    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "c1",
            "to_scan_id": "c2",
            "category": "components",
            "severity": "critical",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
async def test_returns_200_findings(client, db, owner_auth_headers_proj):
    """Happy path: one added finding between two scans of project p."""
    await db["scans"].insert_one(_scan_doc("ok1", "p"))
    await db["scans"].insert_one(_scan_doc("ok2", "p"))
    await db["findings"].insert_one({
        "_id": "f1",
        "project_id": "p",
        "scan_id": "ok2",
        "finding_id": "f1",
        "type": "vulnerability",
        "severity": "critical",
        "component": "x",
        "description": "d",
        "details": {"cve_id": "C-1"},
        "created_at": datetime.now(timezone.utc),
    })

    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "ok1",
            "to_scan_id": "ok2",
            "category": "findings",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["category"] == "findings"
    assert body["from_scan_id"] == "ok1"
    assert body["to_scan_id"] == "ok2"
    assert body["project_id"] == "p"
    assert body["totals"]["added"] == 1
