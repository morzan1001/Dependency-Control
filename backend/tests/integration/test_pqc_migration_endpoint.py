from datetime import datetime, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics.cache import get_analytics_cache


@pytest.fixture(autouse=True)
def _clear_analytics_cache():
    """Reset the process-level analytics cache between tests so each test
    observes its own inputs rather than a stale value from another test."""
    get_analytics_cache().clear()
    yield
    get_analytics_cache().clear()


@pytest.mark.asyncio
async def test_pqc_endpoint_returns_items(client, db, owner_auth_headers_proj):
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert(
        "p",
        "s1",
        [
            CryptoAsset(
                project_id="p",
                scan_id="s1",
                bom_ref="rsa1",
                name="RSA",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.PKE,
                key_size_bits=1024,
            ),
            CryptoAsset(
                project_id="p",
                scan_id="s1",
                bom_ref="ecdsa1",
                name="ECDSA",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.SIGNATURE,
            ),
        ],
    )
    await db.scans.insert_one(
        {
            "_id": "s1",
            "project_id": "p",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resp = await client.get(
        "/api/v1/analytics/crypto/pqc-migration?scope=project&scope_id=p",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scope"] == "project"
    assert body["summary"]["total_items"] >= 2
    top = body["items"][0]
    assert top["source_family"] in {"RSA", "ECDSA"}


@pytest.mark.asyncio
async def test_pqc_endpoint_respects_scope_permission(
    client,
    db,
    member_auth_headers,
):
    resp = await client.get(
        "/api/v1/analytics/crypto/pqc-migration?scope=global",
        headers=member_auth_headers,
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_pqc_endpoint_cache_hit_on_second_call(
    client,
    db,
    owner_auth_headers_proj,
):
    url = "/api/v1/analytics/crypto/pqc-migration?scope=user"
    r1 = await client.get(url, headers=owner_auth_headers_proj)
    r2 = await client.get(url, headers=owner_auth_headers_proj)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["mappings_version"] == r2.json()["mappings_version"]
