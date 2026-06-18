from datetime import datetime, timedelta, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


@pytest.mark.asyncio
async def test_hotspots_endpoint_project_scope(client, db, owner_auth_headers_proj):
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            CryptoAsset(
                project_id="p",
                scan_id="s",
                bom_ref="a",
                name="MD5",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )
    await db.scans.insert_one(
        {
            "_id": "s",
            "project_id": "p",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )
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
            "scope": "project",
            "scope_id": "p",
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
        params=params,
        headers=owner_auth_headers_proj,
    )
    resp2 = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params=params,
        headers=owner_auth_headers_proj,
    )
    assert resp2.status_code == 200
    assert resp2.json().get("cache_hit") is True


@pytest.mark.asyncio
async def test_recommendations_cached_on_second_call(client, db, owner_auth_headers_proj, monkeypatch):
    """The recommendations endpoint must serve the second identical request from
    cache instead of re-loading both scans and re-running the engine (audit #13)."""
    from app.api.v1.endpoints.analytics import recommendations as rec_module

    await db.scans.insert_one(
        {
            "_id": "rs", "project_id": "p", "branch": "main", "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.findings.insert_one(
        {
            "_id": "rf1", "id": "rf1", "project_id": "p", "scan_id": "rs", "finding_id": "CVE-X",
            "type": "vulnerability", "severity": "HIGH", "component": "lib", "version": "1.0",
            "description": "test finding", "details": {}, "scanners": ["osv"],
        }
    )

    # Redis cache_service is a no-op in tests; back it with an in-memory store so
    # the cache actually persists between the two requests.
    class _MemCache:
        def __init__(self):
            self.store = {}

        async def get(self, key):
            return self.store.get(key)

        async def set(self, key, value, ttl_seconds=None):
            self.store[key] = value
            return True

    monkeypatch.setattr(rec_module, "cache_service", _MemCache())

    calls = {"n": 0}
    original = rec_module.recommendation_engine.generate_recommendations

    async def _counting(*args, **kwargs):
        calls["n"] += 1
        return await original(*args, **kwargs)

    monkeypatch.setattr(rec_module.recommendation_engine, "generate_recommendations", _counting)

    path = "/api/v1/analytics/projects/p/recommendations"
    r1 = await client.get(path, headers=owner_auth_headers_proj)
    r2 = await client.get(path, headers=owner_auth_headers_proj)

    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text
    assert r1.json() == r2.json()
    assert calls["n"] == 1  # second request served from cache, engine not re-run
