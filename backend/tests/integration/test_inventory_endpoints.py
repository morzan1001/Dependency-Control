"""Endpoint tests for the inventory stats route."""

from datetime import datetime, timezone

import pytest

_PID = "test-project-id"
_NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


async def _seed_scan(db, scan_id="s1", branch="main"):
    await db.scans.insert_one(
        {"_id": scan_id, "project_id": _PID, "branch": branch, "status": "completed",
         "created_at": _NOW, "commit_hash": "abc123"}
    )


async def _seed_dep(db, scan_id, name, *, direct=False, dep_type="npm", license_id=None, purl=None, version="1.0.0"):
    await db.dependencies.insert_one(
        {"project_id": _PID, "scan_id": scan_id, "name": name, "version": version,
         "type": dep_type, "direct": direct, "license": license_id,
         "purl": purl or f"pkg:{dep_type}/{name}@{version}"}
    )


@pytest.mark.asyncio
async def test_stats_counts_and_scan_context(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", direct=True, license_id="MIT")
    await _seed_dep(db, "s1", "b", license_id="MIT")
    await _seed_dep(db, "s1", "c", dep_type="pypi", license_id="Apache-2.0")

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/stats", headers=member_auth_headers)

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan"] == {"scan_id": "s1", "branch": "main",
                            "created_at": body["scan"]["created_at"], "commit_hash": "abc123"}
    assert body["components_total"] == 3
    assert body["direct_count"] == 1
    assert body["transitive_count"] == 2
    assert body["license_count"] == 2
    assert body["ecosystem_count"] == 2
    assert body["crypto_asset_count"] == 0


@pytest.mark.asyncio
async def test_stats_404_for_branch_without_completed_scan(client, db, member_auth_headers):
    await _seed_scan(db)
    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/stats", params={"branch": "nope"}, headers=member_auth_headers
    )
    assert resp.status_code == 404
    assert "nope" in resp.json()["detail"]
