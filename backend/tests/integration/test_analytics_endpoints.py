import json
from datetime import datetime, timedelta, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.release import Release
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.releases import ReleaseRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

_SCOPE_PATH = "/api/v1/analytics/scope"
_STAGING = "staging"
_OFF_SHAPE_ENVIRONMENT = "Prod.EU"


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


async def _seed_crypto_asset(db, scan_id: str, name: str) -> None:
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        scan_id,
        [
            CryptoAsset(
                project_id="p",
                scan_id=scan_id,
                bom_ref=name,
                name=name,
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )


@pytest.mark.asyncio
async def test_hotspots_pins_the_aggregation_to_an_explicit_scan_id(client, db, owner_auth_headers_proj):
    """?scan_id names the scan to report on; without it the branch head would answer instead."""
    now = datetime.now(timezone.utc)
    for scan_id, name, age_hours in (("s-old", "MD5", 2), ("s-head", "AES", 0)):
        await _seed_crypto_asset(db, scan_id, name)
        await db.scans.insert_one(
            {
                "_id": scan_id,
                "project_id": "p",
                "branch": "main",
                "status": "completed",
                "created_at": now - timedelta(hours=age_hours),
            }
        )

    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "project", "scope_id": "p", "group_by": "name", "scan_id": "s-old"},
        headers=owner_auth_headers_proj,
    )

    assert resp.status_code == 200, resp.text
    assert [item["key"] for item in resp.json()["items"]] == ["MD5"]


@pytest.mark.asyncio
async def test_hotspots_returns_at_most_the_requested_limit(client, db, owner_auth_headers_proj):
    for name in ("MD5", "SHA1", "SHA256", "RSA", "AES"):
        await _seed_crypto_asset(db, "s-lim", name)
    await db.scans.insert_one(
        {
            "_id": "s-lim",
            "project_id": "p",
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "project", "scope_id": "p", "group_by": "name", "limit": 3},
        headers=owner_auth_headers_proj,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["items"]) == 3
    assert body["total"] == 3


@pytest.mark.asyncio
async def test_hotspots_user_scope_accepted(client, db, owner_auth_headers_proj):
    """scope=user must pass the Query regex."""
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "user", "group_by": "name"},
        headers=owner_auth_headers_proj,
    )
    # Accept 200 (resolved to project list) or 403 (no access), never 422.
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
async def test_recommendations_excludes_deleted_branch_scan(client, db, owner_auth_headers_proj):
    """With no explicit scan_id, recommendations use the latest scan on a non-deleted branch, not a newer scan on a deleted branch."""
    await db.projects.update_one({"_id": "p"}, {"$set": {"deleted_branches": ["dead"]}})

    now = datetime.now(timezone.utc)
    # Older scan on an active branch — the one that must be selected.
    await db.scans.insert_one(
        {
            "_id": "scan-active",
            "project_id": "p",
            "branch": "main",
            "status": "completed",
            "created_at": now - timedelta(hours=1),
        }
    )
    # Newer scan on a deleted branch — must be ignored.
    await db.scans.insert_one(
        {
            "_id": "scan-dead",
            "project_id": "p",
            "branch": "dead",
            "status": "completed",
            "created_at": now,
        }
    )

    resp = await client.get(
        "/api/v1/analytics/projects/p/recommendations",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["scan_id"] == "scan-active"


@pytest.mark.asyncio
async def test_recommendations_cached_on_second_call(client, db, owner_auth_headers_proj, monkeypatch):
    """The second identical request is served from cache instead of re-running the engine."""
    from app.api.v1.endpoints.analytics import recommendations as rec_module

    await db.scans.insert_one(
        {
            "_id": "rs",
            "project_id": "p",
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.findings.insert_one(
        {
            "_id": "rf1",
            "id": "rf1",
            "project_id": "p",
            "scan_id": "rs",
            "finding_id": "CVE-X",
            "type": "vulnerability",
            "severity": "HIGH",
            "component": "lib",
            "version": "1.0",
            "description": "test finding",
            "details": {},
            "scanners": ["osv"],
        }
    )

    # Redis cache_service is a no-op in tests; back it with an in-memory store so
    # the cache actually persists between the two requests.
    class _MemCache:
        """Mimics the real CacheService JSON round-trip so cache hits are exercised on JSON-coerced values like production."""

        def __init__(self):
            self.store = {}

        async def get(self, key):
            return self.store.get(key)

        async def set(self, key, value, ttl_seconds=None):
            self.store[key] = json.loads(json.dumps(value, default=str))
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
    assert calls["n"] == 1


def _vuln_finding(_id: str, scan_id: str, cve: str | None = None) -> dict:
    return {
        "_id": _id,
        "id": _id,
        "project_id": "p",
        "scan_id": scan_id,
        "finding_id": cve or _id,
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": "lib",
        "version": "1.0",
        "description": "test finding",
        "details": {"vulnerabilities": [{"id": cve, "severity": "CRITICAL"}]} if cve else {},
        "scanners": ["osv"],
    }


@pytest.mark.asyncio
async def test_recommendations_count_only_vulnerability_findings_as_vulnerabilities(
    client, db, owner_auth_headers_proj
):
    await db.scans.insert_one(
        {
            "_id": "mixed-scan",
            "project_id": "p",
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.findings.insert_one(_vuln_finding("mixed-vuln", "mixed-scan"))
    await db.findings.insert_one(
        {
            "_id": "mixed-secret",
            "id": "mixed-secret",
            "project_id": "p",
            "scan_id": "mixed-scan",
            "finding_id": "aws-key",
            "type": "secret",
            "severity": "HIGH",
            "component": "config.yml",
            "version": None,
            "description": "leaked key",
            "details": {},
            "scanners": ["gitleaks"],
        }
    )

    resp = await client.get("/api/v1/analytics/projects/p/recommendations", headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_findings"] == 2
    assert body["total_vulnerabilities"] == 1
    assert body["summary"]["finding_counts"]["vulnerabilities"] == 1
    assert body["summary"]["finding_counts"]["secrets"] == 1


@pytest.mark.asyncio
async def test_recommendations_recurrence_window_holds_the_newest_scans(
    client, db, owner_auth_headers_proj, monkeypatch
):
    """A CVE present only in the three most recent of fourteen builds is still recurring; the
    window is the newest scans, so it sees them."""
    from app.api.v1.endpoints.analytics import recommendations as rec_module

    async def _no_enrichment(_cves):
        return {}

    monkeypatch.setattr(rec_module, "get_cve_enrichment", _no_enrichment)

    now = datetime.now(timezone.utc)
    scan_count = 14
    scan_ids = [f"win-{i:02d}" for i in range(scan_count)]
    for position, scan_id in enumerate(scan_ids):
        await db.scans.insert_one(
            {
                "_id": scan_id,
                "project_id": "p",
                "branch": "main",
                "status": "completed",
                "created_at": now - timedelta(hours=scan_count - position),
            }
        )
    for scan_id in scan_ids[-3:]:
        await db.findings.insert_one(_vuln_finding(f"f-{scan_id}", scan_id, cve="CVE-2026-7777"))

    resp = await client.get("/api/v1/analytics/projects/p/recommendations", headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scan_id"] == scan_ids[-1]
    recurring = [r for r in body["recommendations"] if r["type"] == "recurring_vulnerability"]
    assert recurring, "the CVE recurs in the last three scans and must be reported as recurring"
    assert "CVE-2026-7777" in recurring[0]["action"]["cves"]


@pytest.mark.asyncio
async def test_scope_denied_unauth(client, db):
    resp = await client.get(_SCOPE_PATH)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_scope_denied_without_any_analytics_permission(client, db, member_auth_headers):
    resp = await client.get(_SCOPE_PATH, headers=member_auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_scope_rejects_an_off_shape_environment(client, db, owner_auth_headers_proj):
    resp = await client.get(
        _SCOPE_PATH, params={"release_environment": _OFF_SHAPE_ENVIRONMENT}, headers=owner_auth_headers_proj
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_scope_lists_the_environments_the_callers_projects_deploy_to(client, db, owner_auth_headers_proj):
    await ReleaseRepository(db).record(
        Release(project_id="p", environment=_STAGING, scan_id="s", released_at=datetime.now(timezone.utc))
    )

    resp = await client.get(_SCOPE_PATH, headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert resp.json()["release_environments"] == [_STAGING]
