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
            "severity": "CRITICAL",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
async def test_returns_200_findings(client, db, owner_auth_headers_proj):
    """Happy path: one added finding between two scans of project p."""
    await db["scans"].insert_one(_scan_doc("ok1", "p"))
    await db["scans"].insert_one(_scan_doc("ok2", "p"))
    await db["findings"].insert_one(
        {
            "_id": "f1",
            "project_id": "p",
            "scan_id": "ok2",
            "finding_id": "f1",
            "type": "vulnerability",
            "severity": "CRITICAL",
            "component": "x",
            "description": "d",
            "details": {"cve_id": "C-1"},
            "created_at": datetime.now(timezone.utc),
        }
    )

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


@pytest.mark.asyncio
async def test_returns_200_components_with_version_change(client, db, owner_auth_headers_proj):
    """category=components surfaces version_changed entries with from/to versions."""
    await db["scans"].insert_one(_scan_doc("cmp_a", "p"))
    await db["scans"].insert_one(_scan_doc("cmp_b", "p"))
    await db["dependencies"].insert_many(
        [
            {
                "_id": "d_a1",
                "project_id": "p",
                "scan_id": "cmp_a",
                "name": "react",
                "version": "17.0.2",
                "purl": "pkg:npm/react@17.0.2",
                "license": "MIT",
                "type": "npm",
            },
            {
                "_id": "d_a2",
                "project_id": "p",
                "scan_id": "cmp_a",
                "name": "left-pad",
                "version": "1.0.0",
                "purl": "pkg:npm/left-pad@1.0.0",
                "license": "WTFPL",
                "type": "npm",
            },
            {
                "_id": "d_b1",
                "project_id": "p",
                "scan_id": "cmp_b",
                "name": "react",
                "version": "18.2.0",
                "purl": "pkg:npm/react@18.2.0",
                "license": "MIT",
                "type": "npm",
            },
            {
                "_id": "d_b2",
                "project_id": "p",
                "scan_id": "cmp_b",
                "name": "axios",
                "version": "1.0.0",
                "purl": "pkg:npm/axios@1.0.0",
                "license": "MIT",
                "type": "npm",
            },
        ]
    )

    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "cmp_a",
            "to_scan_id": "cmp_b",
            "category": "components",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["category"] == "components"
    assert body["totals"]["added"] == 1
    assert body["totals"]["removed"] == 1
    assert body["totals"]["changed"] == 1
    by_change = {i["change"]: i for i in body["items"]}
    assert by_change["version_changed"]["name"] == "react"
    assert by_change["version_changed"]["from_version"] == "17.0.2"
    assert by_change["version_changed"]["to_version"] == "18.2.0"
    assert by_change["added"]["name"] == "axios"
    assert by_change["removed"]["name"] == "left-pad"


@pytest.mark.asyncio
async def test_returns_200_crypto(client, db, owner_auth_headers_proj):
    """category=crypto returns the crypto envelope with added/removed asset items."""
    from app.models.crypto_asset import CryptoAsset
    from app.repositories.crypto_asset import CryptoAssetRepository
    from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

    await db["scans"].insert_one(_scan_doc("cr_a", "p"))
    await db["scans"].insert_one(_scan_doc("cr_b", "p"))
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert(
        "p",
        "cr_a",
        [
            CryptoAsset(
                project_id="p",
                scan_id="cr_a",
                bom_ref="a1",
                name="MD5",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )
    await repo.bulk_upsert(
        "p",
        "cr_b",
        [
            CryptoAsset(
                project_id="p",
                scan_id="cr_b",
                bom_ref="b1",
                name="SHA-256",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )

    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "cr_a",
            "to_scan_id": "cr_b",
            "category": "crypto",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["category"] == "crypto"
    assert body["totals"]["added"] == 1
    assert body["totals"]["removed"] == 1
    names = {i["name"] for i in body["items"]}
    assert names == {"MD5", "SHA-256"}


@pytest.mark.asyncio
async def test_returns_400_for_unknown_severity(client, db, owner_auth_headers_proj):
    """Typo in severity filter must surface as 400, not silently empty results."""
    await db["scans"].insert_many([_scan_doc("ts1", "p"), _scan_doc("ts2", "p")])
    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "ts1",
            "to_scan_id": "ts2",
            "category": "findings",
            "severity": "criticla",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 400, resp.text
    assert "unknown severity" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_returns_400_for_page_size_above_max(client, db, owner_auth_headers_proj):
    """page_size > 200 returns 400 via the orchestrator (not FastAPI auto-422)."""
    await db["scans"].insert_many([_scan_doc("ps1", "p"), _scan_doc("ps2", "p")])
    resp = await client.get(
        BASE,
        params={
            "project_id": "p",
            "from_scan_id": "ps1",
            "to_scan_id": "ps2",
            "category": "findings",
            "page_size": 500,
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 400, resp.text
    assert "page_size" in resp.json()["detail"].lower()
