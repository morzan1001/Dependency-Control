from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

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
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_hotspots_global_requires_permission(client, db, member_auth_headers):
    resp = await client.get(
        "/api/v1/analytics/crypto/hotspots",
        params={"scope": "global", "group_by": "name"},
        headers=member_auth_headers,
    )
    assert resp.status_code == 403


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
    assert resp.status_code == 200, resp.text


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
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_trends_rejects_naive_range_bound(client, db, owner_auth_headers_proj):
    resp = await client.get(
        "/api/v1/analytics/crypto/trends",
        params={
            "scope": "user",
            "range_start": "2026-09-01T00:00:00",
            "range_end": "2026-09-30T00:00:00+00:00",
        },
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_a_second_call_is_served_from_the_cache(client, db, owner_auth_headers_proj):
    params = {"scope": "project", "scope_id": "p", "group_by": "name"}
    resp1 = await client.get(
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
    assert resp2.json()["generated_at"] == resp1.json()["generated_at"]
    assert "cache_hit" not in resp2.json()


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


@pytest.fixture
def _no_enrichment(monkeypatch):
    from app.api.v1.endpoints.analytics import recommendations as rec_module

    monkeypatch.setattr(rec_module.vulnerability_enrichment_service, "enrich_cves", AsyncMock(return_value={}))


@pytest.mark.asyncio
@pytest.mark.usefixtures("_no_enrichment")
async def test_recommendations_recurrence_window_holds_the_newest_scans(client, db, owner_auth_headers_proj):
    """A CVE present only in the three most recent of fourteen builds is still recurring; the
    window is the newest scans, so it sees them."""
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
    assert recurring[0]["action"]["cves"] == [{"cve": "CVE-2026-7777", "components": ["lib"], "scans": 3}]
    assert recurring[0]["affected_components"] == ["lib"]


async def _recurring_cards(client, headers, scan_id: str | None = None) -> list[dict]:
    params = {"scan_id": scan_id} if scan_id else None
    resp = await client.get("/api/v1/analytics/projects/p/recommendations", params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return [r for r in resp.json()["recommendations"] if r["type"] == "recurring_vulnerability"]


async def _seed_build(db, scan_id: str, hours_ago: int, cve: str | None, **fields) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": "p",
            "branch": "main",
            "status": "completed",
            "created_at": datetime.now(timezone.utc) - timedelta(hours=hours_ago),
            **fields,
        }
    )
    if cve:
        await db.findings.insert_one(_vuln_finding(f"f-{scan_id}", scan_id, cve=cve))


@pytest.mark.asyncio
@pytest.mark.usefixtures("_no_enrichment")
async def test_recommendations_recurrence_window_stays_on_the_viewed_scans_branch(client, db, owner_auth_headers_proj):
    """Two feature-branch builds carrying a CVE make it recur there, not in the one main build that has it."""
    await _seed_build(db, "main-old", 5, None)
    await _seed_build(db, "main-head", 3, "CVE-2026-1111")
    await _seed_build(db, "feat-1", 2, "CVE-2026-1111", branch="feature/x")
    await _seed_build(db, "feat-2", 1, "CVE-2026-1111", branch="feature/x")

    assert await _recurring_cards(client, owner_auth_headers_proj, "main-head") == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_no_enrichment")
async def test_recommendations_recurrence_window_counts_a_rescanned_build_once(client, db, owner_auth_headers_proj):
    """Rescans re-analyse one build's commit, so the build and its rescans are one scan of the window."""
    await _seed_build(db, "build", 3, "CVE-2026-3333")
    for index in (1, 2):
        await _seed_build(db, f"rescan-{index}", 3 - index, "CVE-2026-3333", is_rescan=True, original_scan_id="build")

    assert await _recurring_cards(client, owner_auth_headers_proj, "build") == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_no_enrichment")
async def test_recommendations_recurrence_window_holds_the_releases_of_a_project_built_only_from_tags(
    client, db, owner_auth_headers_proj
):
    """A tag pipeline writes its tag into branch, so no two builds of such a project share a branch."""
    for index in range(4):
        tag = f"v1.0.{index}"
        await _seed_build(db, f"tag-{index}", 10 - index, "CVE-2026-4444", branch=tag, commit_tag=tag)

    cards = await _recurring_cards(client, owner_auth_headers_proj)

    assert [card["action"]["cves"] for card in cards] == [[{"cve": "CVE-2026-4444", "components": ["lib"], "scans": 4}]]


@pytest.mark.asyncio
@pytest.mark.usefixtures("_no_enrichment")
async def test_recommendations_recurrence_counts_only_usable_builds_of_the_viewed_branch(
    client, db, owner_auth_headers_proj
):
    window = [
        ("main-old", {}),
        ("feature-1", {"branch": "feature"}),
        ("feature-2", {"branch": "feature"}),
        ("main-rescan", {"is_rescan": True, "original_scan_id": "main-old"}),
        ("main-failed", {"status": "failed"}),
        ("main-head", {}),
    ]
    for hours_ago, (scan_id, fields) in zip(range(len(window), 0, -1), window, strict=True):
        await _seed_build(db, scan_id, hours_ago, "CVE-2026-7777", **fields)

    assert await _recurring_cards(client, owner_auth_headers_proj, "main-head") == []


@pytest.mark.asyncio
async def test_scope_denied_unauth(client, db):
    resp = await client.get(_SCOPE_PATH)
    assert resp.status_code == 401


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
