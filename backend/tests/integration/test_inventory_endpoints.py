"""Endpoint tests for the inventory stats route."""

import csv
import io
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


def _parse_csv(resp) -> list[dict]:
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    text = resp.text
    assert text.startswith("﻿")
    return list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))


async def _seed_lifecycle_finding(db, scan_id, component, version, ftype, latest=None):
    details = {"latest_version": latest} if latest else {}
    await db.findings.insert_one(
        {"project_id": _PID, "scan_id": scan_id, "finding_id": f"{ftype}-{component}",
         "type": ftype, "severity": "LOW", "component": component, "version": version,
         "description": "", "scanners": ["deps_dev"], "details": details, "waived": False}
    )


@pytest.mark.asyncio
async def test_components_page_merges_license_and_lifecycle(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "lodash", direct=True, license_id="MIT", version="4.17.20")
    await _seed_dep(db, "s1", "leftpad", version="0.9.0")
    await _seed_lifecycle_finding(db, "s1", "lodash", "4.17.20", "outdated", latest="4.17.21")
    await _seed_lifecycle_finding(db, "s1", "leftpad", "0.9.0", "eol")
    await db.dependency_enrichments.insert_one(
        {"purl": "pkg:npm/leftpad@0.9.0", "license": "ISC", "license_category": "permissive"}
    )

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components", headers=member_auth_headers
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    by_name = {i["name"]: i for i in body["items"]}
    assert by_name["lodash"]["outdated"] is True
    assert by_name["lodash"]["latest_version"] == "4.17.21"
    assert by_name["lodash"]["license"] == "MIT"
    assert by_name["leftpad"]["eol"] is True
    assert by_name["leftpad"]["license"] == "ISC"          # enrichment fallback
    assert by_name["leftpad"]["license_category"] == "permissive"


@pytest.mark.asyncio
async def test_components_search_and_pagination(client, db, member_auth_headers):
    await _seed_scan(db)
    for i in range(3):
        await _seed_dep(db, "s1", f"pkg-{i}")
    await _seed_dep(db, "s1", "other")

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components",
        params={"search": "pkg-", "page": 1, "page_size": 2},
        headers=member_auth_headers,
    )
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2


@pytest.mark.asyncio
async def test_components_export_streams_all_rows_with_purl(client, db, member_auth_headers):
    await _seed_scan(db)
    for i in range(3):
        await _seed_dep(db, "s1", f"pkg-{i}")

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components/export", headers=member_auth_headers
    )

    assert resp.status_code == 200
    rows = _parse_csv(resp)
    assert len(rows) == 3
    assert rows[0]["purl"].startswith("pkg:npm/")


@pytest.mark.asyncio
async def test_components_export_merges_lifecycle_and_enrichment(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "lodash", version="4.17.20")
    await _seed_dep(db, "s1", "leftpad", version="0.9.0")
    await _seed_lifecycle_finding(db, "s1", "lodash", "4.17.20", "outdated", latest="9.9.9")
    await db.dependency_enrichments.insert_one(
        {"purl": "pkg:npm/leftpad@0.9.0", "license": "ISC", "license_category": "permissive"}
    )

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components/export", headers=member_auth_headers
    )

    by_name = {r["name"]: r for r in _parse_csv(resp)}
    assert by_name["lodash"]["latest_version"] == "9.9.9"
    assert by_name["lodash"]["outdated"] == "true"
    assert by_name["leftpad"]["license"] == "ISC"
    assert by_name["leftpad"]["license_category"] == "permissive"


@pytest.mark.asyncio
async def test_components_sort_by_name_desc_orders_reverse_alphabetically(client, db, member_auth_headers):
    await _seed_scan(db)
    for name in ("alpha", "beta", "gamma"):
        await _seed_dep(db, "s1", name)

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components",
        params={"sort_by": "name", "sort_order": "desc"},
        headers=member_auth_headers,
    )

    assert resp.status_code == 200
    assert [i["name"] for i in resp.json()["items"]] == ["gamma", "beta", "alpha"]


@pytest.mark.asyncio
async def test_components_sort_by_version_ascending(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", version="3.0.0")
    await _seed_dep(db, "s1", "b", version="1.0.0")
    await _seed_dep(db, "s1", "c", version="2.0.0")

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components",
        params={"sort_by": "version", "sort_order": "asc"},
        headers=member_auth_headers,
    )

    assert resp.status_code == 200
    assert [i["version"] for i in resp.json()["items"]] == ["1.0.0", "2.0.0", "3.0.0"]


@pytest.mark.asyncio
async def test_components_invalid_sort_by_falls_back_to_name(client, db, member_auth_headers):
    await _seed_scan(db)
    for name in ("beta", "alpha"):
        await _seed_dep(db, "s1", name)

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components",
        params={"sort_by": "bogus"},
        headers=member_auth_headers,
    )

    assert resp.status_code == 200
    assert [i["name"] for i in resp.json()["items"]] == ["alpha", "beta"]


@pytest.mark.asyncio
async def test_components_sort_by_license_uses_enrichment_fallback(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "dep-a")
    await _seed_dep(db, "s1", "dep-b", license_id="MIT")
    await db.dependency_enrichments.insert_one({"purl": "pkg:npm/dep-a@1.0.0", "license": "ISC"})

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components",
        params={"sort_by": "license", "sort_order": "asc"},
        headers=member_auth_headers,
    )

    assert resp.status_code == 200
    assert [i["name"] for i in resp.json()["items"]] == ["dep-a", "dep-b"]


@pytest.mark.asyncio
async def test_licenses_grouped_with_category_and_unknown_bucket(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", license_id="MIT")
    await _seed_dep(db, "s1", "b", license_id="MIT")
    await _seed_dep(db, "s1", "c", license_id="GPL-3.0-only", purl="pkg:npm/c@1.0.0")
    await _seed_dep(db, "s1", "d")
    await db.dependency_enrichments.insert_one(
        {"purl": "pkg:npm/c@1.0.0", "license": "GPL-3.0-only",
         "license_category": "strong_copyleft", "license_risks": ["copyleft obligations"]}
    )

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/licenses", headers=member_auth_headers)

    assert resp.status_code == 200
    items = {i["license"]: i for i in resp.json()["items"]}
    assert items["MIT"]["component_count"] == 2
    assert sorted(items["MIT"]["components"]) == ["a@1.0.0", "b@1.0.0"]
    assert items["GPL-3.0-only"]["category"] == "strong_copyleft"
    assert items["GPL-3.0-only"]["risks"] == ["copyleft obligations"]
    assert items["unknown"]["component_count"] == 1


@pytest.mark.asyncio
async def test_licenses_export_contains_full_component_list(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", license_id="MIT")
    await _seed_dep(db, "s1", "b", license_id="MIT")

    rows = _parse_csv(
        await client.get(f"/api/v1/projects/{_PID}/inventory/licenses/export", headers=member_auth_headers)
    )
    assert rows[0]["license"] == "MIT"
    assert rows[0]["component_count"] == "2"
    assert "a@1.0.0" in rows[0]["components"]
    assert "b@1.0.0" in rows[0]["components"]
