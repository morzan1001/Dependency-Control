"""Endpoint tests for the inventory stats route."""

import csv
import io
from datetime import datetime, timezone

import pytest

from app.services.analyzers.license_compliance import LicenseAnalyzer

_PID = "test-project-id"
_NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


async def _seed_scan(db, scan_id="s1", branch="main"):
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": _PID,
            "branch": branch,
            "status": "completed",
            "created_at": _NOW,
            "commit_hash": "abc123",
        }
    )


async def _seed_dep(
    db,
    scan_id,
    name,
    *,
    direct=False,
    dep_type="npm",
    license_id=None,
    purl=None,
    version="1.0.0",
    license_category=None,
    license_risks=None,
):
    doc = {
        "project_id": _PID,
        "scan_id": scan_id,
        "name": name,
        "version": version,
        "type": dep_type,
        "direct": direct,
        "license": license_id,
        "purl": purl or f"pkg:{dep_type}/{name}@{version}",
    }
    if license_category is not None:
        doc["license_category"] = license_category
    if license_risks is not None:
        doc["license_risks"] = license_risks
    await db.dependencies.insert_one(doc)


async def _seed_crypto(db, scan_id, name, *, asset_type="algorithm", primitive=None, locations=None):
    await db.crypto_assets.insert_one(
        {
            "project_id": _PID,
            "scan_id": scan_id,
            "bom_ref": name,
            "name": name,
            "asset_type": asset_type,
            "primitive": primitive,
            "occurrence_locations": locations or [],
        }
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
    assert body["scan"] == {
        "scan_id": "s1",
        "branch": "main",
        "created_at": body["scan"]["created_at"],
        "commit_hash": "abc123",
    }
    assert body["components_total"] == 3
    assert body["direct_count"] == 1
    assert body["transitive_count"] == 2
    assert body["license_count"] == 2
    assert body["ecosystem_count"] == 2
    assert body["crypto_asset_count"] == 0


@pytest.mark.asyncio
async def test_stats_license_count_counts_tokenized_units(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", license_id="MIT")
    await _seed_dep(db, "s1", "b", license_id="MIT AND GPL-3.0-only")
    await _seed_dep(db, "s1", "c", license_id="GPL-3.0-only")

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/stats", headers=member_auth_headers)

    assert resp.status_code == 200
    assert resp.json()["license_count"] == 2


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
    # The lifecycle normalizer persists the newest version as fixed_version.
    details = {"fixed_version": latest} if latest else {}
    await db.findings.insert_one(
        {
            "project_id": _PID,
            "scan_id": scan_id,
            "finding_id": f"{ftype}-{component}",
            "type": ftype,
            "severity": "LOW",
            "component": component,
            "version": version,
            "description": "",
            "scanners": ["deps_dev"],
            "details": details,
            "waived": False,
        }
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

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/components", headers=member_auth_headers)

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    by_name = {i["name"]: i for i in body["items"]}
    assert by_name["lodash"]["outdated"] is True
    assert by_name["lodash"]["latest_version"] == "4.17.21"
    assert by_name["lodash"]["license"] == "MIT"
    assert by_name["leftpad"]["eol"] is True
    # The scan's own record is authoritative; another scan's enrichment does not name this one's license.
    assert by_name["leftpad"]["license"] is None
    assert by_name["leftpad"]["license_category"] is None


@pytest.mark.asyncio
async def test_components_page_reads_license_category_from_dependency_doc(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "c", license_id="GPL-3.0-only", license_category="strong_copyleft")

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/components", headers=member_auth_headers)

    assert resp.status_code == 200
    item = resp.json()["items"][0]
    assert item["license_category"] == "strong_copyleft"


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

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/components/export", headers=member_auth_headers)

    assert resp.status_code == 200
    rows = _parse_csv(resp)
    assert len(rows) == 3
    assert rows[0]["purl"].startswith("pkg:npm/")


@pytest.mark.asyncio
async def test_components_export_merges_lifecycle_and_takes_the_scans_license(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "lodash", version="4.17.20")
    await _seed_dep(db, "s1", "leftpad", version="0.9.0")
    await _seed_lifecycle_finding(db, "s1", "lodash", "4.17.20", "outdated", latest="9.9.9")
    await db.dependency_enrichments.insert_one(
        {"purl": "pkg:npm/leftpad@0.9.0", "license": "ISC", "license_category": "permissive"}
    )

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/components/export", headers=member_auth_headers)

    by_name = {r["name"]: r for r in _parse_csv(resp)}
    assert by_name["lodash"]["latest_version"] == "9.9.9"
    assert by_name["lodash"]["outdated"] == "true"
    assert by_name["leftpad"]["license"] == ""
    assert by_name["leftpad"]["license_category"] == ""


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
async def test_components_sort_by_license_orders_by_the_scans_license(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "dep-a", license_id="MIT")
    await _seed_dep(db, "s1", "dep-b", license_id="Apache-2.0")
    await _seed_dep(db, "s1", "dep-c")
    await db.dependency_enrichments.insert_one({"purl": "pkg:npm/dep-c@1.0.0", "license": "Zlib"})

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/components",
        params={"sort_by": "license", "sort_order": "asc"},
        headers=member_auth_headers,
    )

    assert resp.status_code == 200
    assert [i["name"] for i in resp.json()["items"]] == ["dep-c", "dep-b", "dep-a"]


@pytest.mark.asyncio
async def test_licenses_grouped_with_category_and_unknown_bucket(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", license_id="MIT")
    await _seed_dep(db, "s1", "b", license_id="MIT")
    await _seed_dep(db, "s1", "c", license_id="GPL-3.0-only")
    await _seed_dep(db, "s1", "d")

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/licenses", headers=member_auth_headers)

    assert resp.status_code == 200
    items = {i["license"]: i for i in resp.json()["items"]}
    assert items["MIT"]["component_count"] == 2
    assert sorted(items["MIT"]["components"]) == ["a@1.0.0", "b@1.0.0"]
    assert items["GPL-3.0-only"]["category"] == "strong_copyleft"
    assert items["unknown"]["component_count"] == 1


@pytest.mark.asyncio
async def test_the_tiles_count_what_the_tables_show(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", license_id="MIT")
    await _seed_dep(db, "s1", "b", license_id="Apache-2.0", dep_type="")
    await _seed_dep(db, "s1", "c")

    stats = (await client.get(f"/api/v1/projects/{_PID}/inventory/stats", headers=member_auth_headers)).json()
    licenses = (await client.get(f"/api/v1/projects/{_PID}/inventory/licenses", headers=member_auth_headers)).json()
    components = (await client.get(f"/api/v1/projects/{_PID}/inventory/components", headers=member_auth_headers)).json()

    assert stats["license_count"] == len(licenses["items"]) == 3
    assert stats["ecosystem_count"] == len({i["ecosystem"] for i in components["items"]}) == 2


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


@pytest.mark.asyncio
async def test_licenses_tokenizes_composite_spdx_expressions(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_dep(db, "s1", "a", license_id="LGPL-2.1-or-later AND BSD-3-Clause")
    await _seed_dep(db, "s1", "b", license_id="BSD-3-Clause")

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/licenses", headers=member_auth_headers)

    assert resp.status_code == 200
    items = {i["license"]: i for i in resp.json()["items"]}
    assert items["BSD-3-Clause"]["component_count"] == 2
    assert items["LGPL-2.1-or-later"]["component_count"] == 1
    assert not any(" AND " in license_id for license_id in items)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_each_license_row_classifies_its_id_as_the_license_analyzer_does(client, db, member_auth_headers):
    await _seed_scan(db)
    # The analysis stamps a composite's most restrictive or chosen member, and a URL-resolved license, onto the row.
    await _seed_dep(
        db,
        "s1",
        "a",
        license_id="MIT AND GPL-3.0-only",
        license_category="strong_copyleft",
        license_risks=["Cannot be combined with proprietary code"],
    )
    await _seed_dep(
        db,
        "s1",
        "b",
        license_id="Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0",
        license_category="permissive",
    )
    await _seed_dep(db, "s1", "c", license_id="LicenseRef-acme", license_category="permissive")
    await _seed_dep(db, "s1", "d")

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/licenses", headers=member_auth_headers)

    rows = {item["license"]: (item["category"], item["risks"]) for item in resp.json()["items"]}
    expected = {}
    for license_id in rows:
        result = await LicenseAnalyzer().analyze({}, parsed_components=[{"name": "x", "license": license_id}])
        recorded = result["component_licenses"]
        expected[license_id] = (recorded[0]["category"], recorded[0]["risks"]) if recorded else (None, [])
    assert {license_id: category for license_id, (category, _) in expected.items()} == {
        "MIT": "permissive",
        "GPL-3.0-only": "strong_copyleft",
        "Apache-2.0": "permissive",
        "GPL-2.0-only WITH Classpath-exception-2.0": "weak_copyleft",
        "LicenseRef-acme": None,
        "unknown": None,
    }
    assert rows == expected


@pytest.mark.asyncio
async def test_crypto_page_and_export(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_crypto(db, "s1", "AES-256-GCM", primitive="block-cipher", locations=["src/a.py", "src/b.py"])
    await _seed_crypto(db, "s1", "MD5", primitive="hash")

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/crypto", headers=member_auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    aes = next(i for i in body["items"] if i["name"] == "AES-256-GCM")
    assert aes["location_count"] == 2

    rows = _parse_csv(await client.get(f"/api/v1/projects/{_PID}/inventory/crypto/export", headers=member_auth_headers))
    assert {r["name"] for r in rows} == {"AES-256-GCM", "MD5"}
    assert next(r for r in rows if r["name"] == "AES-256-GCM")["locations"] == "src/a.py; src/b.py"


@pytest.mark.asyncio
async def test_crypto_search_respects_total_count(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_crypto(db, "s1", "AES-128-GCM")
    await _seed_crypto(db, "s1", "AES-256-GCM")
    await _seed_crypto(db, "s1", "MD5")

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/crypto",
        params={"search": "AES", "page": 1, "page_size": 1},
        headers=member_auth_headers,
    )
    body = resp.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1


@pytest.mark.asyncio
async def test_crypto_search_escapes_regex_metacharacters(client, db, member_auth_headers):
    await _seed_scan(db)
    await _seed_crypto(db, "s1", "AES-256-GCM")

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/crypto",
        params={"search": "["},
        headers=member_auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 0

    await _seed_crypto(db, "s1", "AES[legacy]")

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/crypto",
        params={"search": "AES["},
        headers=member_auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


_INVENTORY_ROUTES = [
    "stats",
    "components",
    "components/export",
    "licenses",
    "licenses/export",
    "crypto",
    "crypto/export",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _INVENTORY_ROUTES)
async def test_every_inventory_route_refuses_a_non_member(client, db, owner_auth_headers_proj_p2, route):
    await _seed_scan(db)

    resp = await client.get(f"/api/v1/projects/{_PID}/inventory/{route}", headers=owner_auth_headers_proj_p2)

    assert resp.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _INVENTORY_ROUTES)
async def test_every_inventory_route_404s_a_branch_without_a_scan(client, db, member_auth_headers, route):
    await _seed_scan(db)

    resp = await client.get(
        f"/api/v1/projects/{_PID}/inventory/{route}", params={"branch": "gone"}, headers=member_auth_headers
    )

    assert resp.status_code == 404
    assert resp.json()["detail"] == "No completed scan found for branch 'gone'"
