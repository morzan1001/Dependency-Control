from datetime import datetime, timedelta, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


@pytest.mark.asyncio
async def test_hotspots_endpoint_project_scope(client, db, owner_auth_headers_proj):
    await CryptoAssetRepository(db).bulk_upsert("p", "s", [
        CryptoAsset(project_id="p", scan_id="s", bom_ref="a",
                    name="MD5", asset_type=CryptoAssetType.ALGORITHM,
                    primitive=CryptoPrimitive.HASH),
    ])
    await db.scans.insert_one({
        "_id": "s", "project_id": "p",
        "status": "completed", "created_at": datetime.now(timezone.utc),
    })
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "project", "scope_id": "p", "group_by": "name"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scope"] == "project"
    assert body["grouping_dimension"] == "name"


@pytest.mark.asyncio
async def test_hotspots_denied_unauth(client, db):
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "project", "scope_id": "p", "group_by": "name"},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_hotspots_global_requires_permission(client, db, member_auth_headers):
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "global", "group_by": "name"},
        headers=member_auth_headers,
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_trends_endpoint(client, db, owner_auth_headers_proj):
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/api/v1/analytics/crypto/trends",
        params={
            "scope": "project", "scope_id": "p",
            "metric": "total_crypto_findings",
            "bucket": "week",
            "range_start": (now - timedelta(days=30)).isoformat(),
            "range_end": now.isoformat(),
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["metric"] == "total_crypto_findings"


@pytest.mark.asyncio
async def test_scan_delta_endpoint(client, db, owner_auth_headers_proj):
    await CryptoAssetRepository(db).bulk_upsert("p", "s1", [
        CryptoAsset(project_id="p", scan_id="s1", bom_ref="a",
                    name="MD5", asset_type=CryptoAssetType.ALGORITHM),
    ])
    await CryptoAssetRepository(db).bulk_upsert("p", "s2", [
        CryptoAsset(project_id="p", scan_id="s2", bom_ref="b",
                    name="SHA-256", asset_type=CryptoAssetType.ALGORITHM),
    ])
    resp = await client.get(
        "/api/v1/analytics/crypto/scan-delta",
        params={"project_id": "p", "from": "s1", "to": "s2"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["from_scan_id"] == "s1"
    assert body["to_scan_id"] == "s2"


@pytest.mark.asyncio
async def test_hotspots_user_scope_accepted(client, db, owner_auth_headers_proj):
    """scope=user must pass the Query regex (regression guard)."""
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "user", "group_by": "name"},
        headers=owner_auth_headers_proj,
    )
    # Accept 200 (resolved to project list) or 403 (no access). NOT 422.
    assert resp.status_code != 422, resp.text


@pytest.mark.asyncio
async def test_trends_user_scope_accepted(client, db, owner_auth_headers_proj):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/api/v1/analytics/crypto/trends",
        params={
            "scope": "user",
            "metric": "total_crypto_findings",
            "bucket": "week",
            "range_start": (now - timedelta(days=30)).isoformat(),
            "range_end": now.isoformat(),
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code != 422, resp.text


@pytest.mark.asyncio
async def test_cache_hit_on_second_call(client, db, owner_auth_headers_proj):
    params = {"scope": "project", "scope_id": "p", "group_by": "name"}
    await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params=params, headers=owner_auth_headers_proj,
    )
    resp2 = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params=params, headers=owner_auth_headers_proj,
    )
    assert resp2.status_code == 200
    assert resp2.json().get("cache_hit") is True
