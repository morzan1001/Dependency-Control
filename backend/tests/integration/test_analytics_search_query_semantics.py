"""The two analytics search endpoints hand the caller's query and sort order straight to Mongo.

The query text becomes a ``$regex`` and the sort order becomes the direction of a skip/limit page,
so a query that is not escaped and a direction that is inverted both change which rows a caller is
shown without any Python-side pass to repair them.
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

_SCAN_ID = "scan-search"
_SEARCH_PATH = "/api/v1/analytics/search"
_VULN_SEARCH_PATH = "/api/v1/analytics/vulnerability-search"
_CVE = "CVE-2026-9001"


def _dependency(name: str) -> dict:
    return {
        "_id": f"dep-{name}",
        "scan_id": _SCAN_ID,
        "project_id": "p",
        "name": name,
        "version": "1.0.0",
        "type": "npm",
        "direct": True,
    }


def _vulnerability(component: str, waived: bool = False) -> dict:
    return {
        "_id": f"finding-{component}",
        "id": f"{component}:1.0.0",
        "finding_id": f"{component}:1.0.0",
        "description": "",
        "scanners": ["trivy"],
        "scan_id": _SCAN_ID,
        "project_id": "p",
        "type": "vulnerability",
        "severity": "HIGH",
        "component": component,
        "version": "1.0.0",
        "waived": waived,
        "waiver_reason": "accepted risk" if waived else None,
        "details": {"vulnerabilities": [{"id": _CVE, "severity": "HIGH", "aliases": []}]},
    }


@pytest_asyncio.fixture
async def scanned(db, owner_auth_headers_proj):
    await db.scans.insert_one(
        {
            "_id": _SCAN_ID,
            "project_id": "p",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": _SCAN_ID}})
    return owner_auth_headers_proj


@pytest.mark.asyncio
async def test_dependency_search_matches_the_query_literally(client, db, scanned):
    await db.dependencies.insert_one(_dependency("l.dash"))
    await db.dependencies.insert_one(_dependency("lodash"))

    resp = await client.get(_SEARCH_PATH, params={"q": "l.dash"}, headers=scanned)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [row["package"] for row in body["items"]] == ["l.dash"]
    assert body["total"] == 1


@pytest.mark.asyncio
async def test_dependency_search_accepts_a_query_with_unbalanced_metacharacters(client, db, scanned):
    await db.dependencies.insert_one(_dependency("lodash"))

    resp = await client.get(_SEARCH_PATH, params={"q": "lodash("}, headers=scanned)

    assert resp.status_code == 200, resp.text
    assert resp.json()["items"] == []


@pytest.mark.asyncio
async def test_dependency_search_pages_ascending_from_the_first_name(client, db, scanned):
    for name in ("omega-lib", "alpha-lib", "zeta-lib"):
        await db.dependencies.insert_one(_dependency(name))

    resp = await client.get(
        _SEARCH_PATH,
        params={"q": "lib", "sort_by": "name", "sort_order": "asc", "limit": 1},
        headers=scanned,
    )

    assert resp.status_code == 200, resp.text
    assert [row["package"] for row in resp.json()["items"]] == ["alpha-lib"]


@pytest.mark.asyncio
async def test_dependency_search_pages_descending_from_the_last_name(client, db, scanned):
    for name in ("omega-lib", "alpha-lib", "zeta-lib"):
        await db.dependencies.insert_one(_dependency(name))

    resp = await client.get(
        _SEARCH_PATH,
        params={"q": "lib", "sort_by": "name", "sort_order": "desc", "limit": 1},
        headers=scanned,
    )

    assert resp.status_code == 200, resp.text
    assert [row["package"] for row in resp.json()["items"]] == ["zeta-lib"]


@pytest.mark.asyncio
async def test_vulnerability_search_returns_the_unwaived_finding(client, db, scanned):
    await db.findings.insert_one(_vulnerability("left-pad"))
    await db.findings.insert_one(_vulnerability("waived-pkg", waived=True))

    resp = await client.get(_VULN_SEARCH_PATH, params={"q": _CVE}, headers=scanned)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [row["component"] for row in body["items"]] == ["left-pad"]
    assert body["total"] == 1


@pytest.mark.asyncio
async def test_vulnerability_search_with_include_waived_returns_both(client, db, scanned):
    await db.findings.insert_one(_vulnerability("left-pad"))
    await db.findings.insert_one(_vulnerability("waived-pkg", waived=True))

    resp = await client.get(_VULN_SEARCH_PATH, params={"q": _CVE, "include_waived": "true"}, headers=scanned)

    assert resp.status_code == 200, resp.text
    assert sorted(row["component"] for row in resp.json()["items"]) == ["left-pad", "waived-pkg"]


@pytest.mark.asyncio
async def test_vulnerability_search_pages_descending_from_the_last_component(client, db, scanned):
    for component in ("mid-pkg", "alpha-pkg", "zeta-pkg"):
        await db.findings.insert_one(_vulnerability(component))

    resp = await client.get(
        _VULN_SEARCH_PATH,
        params={"q": _CVE, "sort_by": "component", "sort_order": "desc", "limit": 1},
        headers=scanned,
    )

    assert resp.status_code == 200, resp.text
    assert [row["component"] for row in resp.json()["items"]] == ["zeta-pkg"]


@pytest.mark.asyncio
async def test_vulnerability_search_pages_ascending_from_the_first_component(client, db, scanned):
    for component in ("mid-pkg", "alpha-pkg", "zeta-pkg"):
        await db.findings.insert_one(_vulnerability(component))

    resp = await client.get(
        _VULN_SEARCH_PATH,
        params={"q": _CVE, "sort_by": "component", "sort_order": "asc", "limit": 1},
        headers=scanned,
    )

    assert resp.status_code == 200, resp.text
    assert [row["component"] for row in resp.json()["items"]] == ["alpha-pkg"]
