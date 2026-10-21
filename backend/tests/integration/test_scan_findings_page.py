"""A findings page streams its rows instead of building them into one document, and one finding reads on its own."""

import pytest

from tests.helpers.databases import DATABASES

pytestmark = pytest.mark.asyncio

_SCAN = "scan-page"
_GO_MODULE = "github.com/docker/docker"
_GO_VERSION = "v20.10.7+incompatible"


def _finding(i: int, **overrides) -> dict:
    return {
        "_id": f"f-{i:04}",
        "finding_id": f"CVE-2026-{i:04}",
        "scan_id": _SCAN,
        "project_id": "p",
        "type": "vulnerability",
        "severity": "HIGH",
        "component": f"lib{i}",
        "version": "1.0",
        "description": "",
        "scanners": ["trivy"],
        "waived": False,
        **overrides,
    }


async def _seed_scan(db) -> None:
    await db.scans.insert_one({"_id": _SCAN, "project_id": "p", "branch": "main", "status": "completed"})


@pytest.mark.live_mongo
async def test_a_page_larger_than_one_bson_document_is_answered(client, db, owner_auth_headers_proj):
    """500 rows of ~40 KB overflow the 16 MB a single aggregation result document may hold."""
    await _seed_scan(db)
    bulky = {"advisory": "x" * 40_000}
    await db.findings.insert_many([_finding(i, details=bulky) for i in range(500)])

    resp = await client.get(
        f"/api/v1/projects/scans/{_SCAN}/findings", params={"limit": 500}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 200, resp.text[:300]
    assert (resp.json()["total"], len(resp.json()["items"])) == (500, 500)


@pytest.mark.parametrize("database", DATABASES)
async def test_the_direct_only_total_counts_after_the_dependency_join(client, db, database, owner_auth_headers_proj):
    await _seed_scan(db)
    await db.findings.insert_many([_finding(i) for i in range(5)])
    await db.dependencies.insert_many(
        [{"_id": f"d-{i}", "scan_id": _SCAN, "name": f"lib{i}", "version": "1.0", "direct": i >= 2} for i in range(4)]
    )
    url = f"/api/v1/projects/scans/{_SCAN}/findings"

    every = (await client.get(url, params={"limit": 2}, headers=owner_auth_headers_proj)).json()
    direct = (await client.get(url, params={"limit": 2, "direct_only": True}, headers=owner_auth_headers_proj)).json()

    # lib0 and lib1 are transitive; lib4 has no inventory row, so its finding stays.
    assert (every["total"], len(every["items"])) == (5, 2)
    assert (direct["total"], len(direct["items"])) == (3, 2)


@pytest.mark.parametrize("database", DATABASES)
async def test_one_finding_reads_with_the_columns_of_its_page_row(client, db, database, owner_auth_headers_proj):
    await _seed_scan(db)
    finding_id = f"{_GO_MODULE}:{_GO_VERSION}"
    await db.findings.insert_many(
        [
            _finding(1, finding_id=finding_id, component=_GO_MODULE, version=_GO_VERSION),
            _finding(2),
        ]
    )
    await db.dependencies.insert_one(
        {
            "_id": "d-go",
            "scan_id": _SCAN,
            "name": _GO_MODULE,
            "version": _GO_VERSION,
            "purl": f"pkg:golang/{_GO_MODULE}@{_GO_VERSION}",
            "direct": True,
        }
    )

    one = await client.get(f"/api/v1/projects/scans/{_SCAN}/findings/{finding_id}", headers=owner_auth_headers_proj)
    [row] = (
        await client.get(
            f"/api/v1/projects/scans/{_SCAN}/findings", params={"search": _GO_MODULE}, headers=owner_auth_headers_proj
        )
    ).json()["items"]

    assert one.status_code == 200, one.text
    assert one.json() == row
    assert (one.json()["id"], one.json()["purl"]) == (finding_id, f"pkg:golang/{_GO_MODULE}@{_GO_VERSION}")


@pytest.mark.parametrize("database", DATABASES)
async def test_of_findings_sharing_an_id_the_most_severe_is_read(client, db, database, owner_auth_headers_proj):
    """A license id names every package under that license."""
    await _seed_scan(db)
    shared = {"finding_id": "LIC-GPL-3.0", "type": "license"}
    await db.findings.insert_many(
        [
            _finding(1, severity="LOW", component="alpha", **shared),
            _finding(2, severity="CRITICAL", component="beta", **shared),
        ]
    )

    resp = await client.get(f"/api/v1/projects/scans/{_SCAN}/findings/LIC-GPL-3.0", headers=owner_auth_headers_proj)

    assert (resp.status_code, resp.json()["component"]) == (200, "beta")


@pytest.mark.parametrize("database", DATABASES)
async def test_a_finding_sharing_its_id_reads_by_its_component_and_version(
    client, db, database, owner_auth_headers_proj
):
    await _seed_scan(db)
    shared = {"finding_id": "LIC-GPL-3.0", "type": "license"}
    await db.findings.insert_many(
        [
            _finding(1, severity="LOW", component="alpha", version="1.0", **shared),
            _finding(2, severity="CRITICAL", component="beta", version="1.0", **shared),
            _finding(3, severity="CRITICAL", component="beta", version="2.0", **shared),
        ]
    )
    url = f"/api/v1/projects/scans/{_SCAN}/findings/LIC-GPL-3.0"

    alpha = await client.get(url, params={"component": "alpha"}, headers=owner_auth_headers_proj)
    beta = await client.get(url, params={"component": "beta", "version": "2.0"}, headers=owner_auth_headers_proj)
    missing = await client.get(url, params={"component": "gamma"}, headers=owner_auth_headers_proj)

    assert (alpha.status_code, alpha.json()["component"], alpha.json()["severity"]) == (200, "alpha", "LOW")
    assert (beta.status_code, beta.json()["component"], beta.json()["version"]) == (200, "beta", "2.0")
    assert missing.status_code == 404


@pytest.mark.parametrize("database", DATABASES)
async def test_an_unknown_finding_is_not_found(client, db, database, owner_auth_headers_proj):
    await _seed_scan(db)
    await db.findings.insert_one(_finding(1))

    resp = await client.get(f"/api/v1/projects/scans/{_SCAN}/findings/CVE-1999-0001", headers=owner_auth_headers_proj)

    assert (resp.status_code, resp.json()["detail"]) == (404, "Finding not found")
