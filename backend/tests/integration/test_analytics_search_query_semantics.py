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


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [_SEARCH_PATH, _VULN_SEARCH_PATH])
async def test_an_empty_scope_reports_the_first_page_as_page_one(client, owner_auth_headers_proj, path):
    resp = await client.get(path, params={"q": "anything"}, headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert resp.json()["page"] == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_vulnerability_search_finds_a_high_cve_inside_a_critical_component(client, db, scanned):
    finding = _vulnerability("log4j-core")
    finding["severity"] = "CRITICAL"
    finding["details"]["vulnerabilities"] = [
        {"id": "CVE-2026-9002", "severity": "CRITICAL", "aliases": []},
        {"id": _CVE, "severity": "HIGH", "aliases": []},
    ]
    await db.findings.insert_one(finding)

    resp = await client.get(_VULN_SEARCH_PATH, params={"q": "CVE-2026-900", "severity": "HIGH"}, headers=scanned)

    assert resp.status_code == 200, resp.text
    assert [row["vulnerability_id"] for row in resp.json()["items"]] == [_CVE]


async def _pages(client, path: str, headers: dict, params: dict, count: int) -> list[dict]:
    pages = []
    for skip in range(count):
        resp = await client.get(path, params={**params, "limit": 1, "skip": skip}, headers=headers)
        assert resp.status_code == 200, resp.text
        pages.append(resp.json())
    return pages


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(
    ("param", "field", "value"), [("in_kev", "in_kev", True), ("has_fix", "fixed_version", "1.0.1")]
)
async def test_an_advisory_filter_fills_every_page_and_counts_only_matching_findings(
    client, db, scanned, param, field, value
):
    for component, matches in (("a-pkg", True), ("b-pkg", False), ("c-pkg", True), ("d-pkg", False)):
        finding = _vulnerability(component)
        if matches:
            finding["details"]["vulnerabilities"][0][field] = value
        await db.findings.insert_one(finding)

    params = {"q": _CVE, param: "true", "sort_by": "component", "sort_order": "asc"}
    pages = await _pages(client, _VULN_SEARCH_PATH, scanned, params, 2)

    assert [row["component"] for page in pages for row in page["items"]] == ["a-pkg", "c-pkg"]
    assert pages[0]["total"] == 2


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_kev_filter_skips_a_finding_whose_kev_advisory_the_query_does_not_name(client, db, scanned):
    finding = _vulnerability("log4j-core")
    finding["details"] = {
        "in_kev": True,
        "vulnerabilities": [
            {"id": "CVE-2021-44228", "severity": "HIGH", "in_kev": True},
            {"id": _CVE, "severity": "HIGH", "aliases": []},
        ],
    }
    await db.findings.insert_one(finding)

    resp = await client.get(_VULN_SEARCH_PATH, params={"q": _CVE, "in_kev": "true"}, headers=scanned)

    assert resp.status_code == 200, resp.text
    assert (resp.json()["items"], resp.json()["total"]) == ([], 0)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_severity_sort_pages_from_the_most_severe_finding(client, db, scanned):
    for component, severity in (("a-pkg", "LOW"), ("b-pkg", "CRITICAL"), ("c-pkg", "MEDIUM"), ("d-pkg", "HIGH")):
        finding = _vulnerability(component)
        finding["severity"] = severity
        finding["details"]["vulnerabilities"][0]["severity"] = severity
        await db.findings.insert_one(finding)

    params = {"q": _CVE, "sort_by": "severity", "sort_order": "desc"}
    pages = await _pages(client, _VULN_SEARCH_PATH, scanned, params, 4)

    assert [row["severity"] for page in pages for row in page["items"]] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_description_match_reaches_only_non_vulnerability_findings(client, db, scanned):
    vulnerability = _vulnerability("left-pad")
    vulnerability["description"] = "frobnicator overflow"
    license_finding = {
        **_vulnerability("gpl-pkg"),
        "_id": "finding-license",
        "type": "license",
        "description": "frobnicator ships under GPL-3.0",
        "details": {},
    }
    await db.findings.insert_many([vulnerability, license_finding])

    resp = await client.get(_VULN_SEARCH_PATH, params={"q": "frobnicator"}, headers=scanned)

    assert resp.status_code == 200, resp.text
    assert [row["finding_type"] for row in resp.json()["items"]] == ["license"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_vulnerability_filter_fills_the_page_and_counts_only_vulnerable_dependencies(client, db, scanned):
    for name in ("alpha-lib", "beta-lib", "zeta-lib"):
        await db.dependencies.insert_one(_dependency(name))
    await db.findings.insert_one(_vulnerability("zeta-lib"))

    resp = await client.get(
        _SEARCH_PATH, params={"q": "lib", "has_vulnerabilities": "true", "limit": 1}, headers=scanned
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [row["package"] for row in body["items"]] == ["zeta-lib"]
    assert body["total"] == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("finding", [{"scan_id": "scan-older"}, {"waived": True}], ids=["older scan", "waived"])
async def test_the_vulnerability_filter_ignores_an_older_scan_s_and_a_waived_finding(client, db, scanned, finding):
    await db.dependencies.insert_one(_dependency("lodash"))
    await db.findings.insert_one({**_vulnerability("lodash"), **finding})

    resp = await client.get(_SEARCH_PATH, params={"q": "lodash", "has_vulnerabilities": "false"}, headers=scanned)

    assert resp.status_code == 200, resp.text
    assert [row["package"] for row in resp.json()["items"]] == ["lodash"]
