from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.api.v1.endpoints.analytics import dependencies as tree_module
from app.repositories.dependencies import DependencyRepository
from app.services.recommendation.common import get_attr
from app.services.dependency_store import store_scan_dependencies
from app.services.sbom_parser import parse_sbom

_OWN_PROJECT = "p"
_FOREIGN_PROJECT = "p2"
_OWN_SCAN = "scan-own"
_FOREIGN_SCAN = "scan-foreign"
_OWN_PACKAGE = "own-lib"
_FOREIGN_PACKAGE = "foreign-secret-lib"


def _scan(scan_id: str, project_id: str) -> dict:
    return {
        "_id": scan_id,
        "project_id": project_id,
        "branch": "main",
        "status": "completed",
        "created_at": datetime.now(timezone.utc),
    }


def _dependency(_id: str, scan_id: str, project_id: str, name: str) -> dict:
    return {
        "_id": _id,
        "scan_id": scan_id,
        "project_id": project_id,
        "name": name,
        "version": "1.0.0",
        "purl": f"pkg:pypi/{name}@1.0.0",
        "type": "pypi",
        "direct": True,
        "parent_components": [],
    }


def _vulnerability(_id: str, scan_id: str, project_id: str, component: str, severity: str) -> dict:
    return {
        "_id": _id,
        "id": f"CVE-2026-{_id}",
        "finding_id": f"CVE-2026-{_id}",
        "scan_id": scan_id,
        "project_id": project_id,
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": "1.0.0",
        "description": "",
        "scanners": ["trivy"],
        "waived": False,
        "details": {"vulnerabilities": [{"id": f"CVE-2026-{_id}", "severity": severity, "aliases": []}]},
    }


@pytest_asyncio.fixture
async def seeded(db, owner_auth_headers_proj, owner_auth_headers_proj_p2):
    await db.scans.insert_many([_scan(_OWN_SCAN, _OWN_PROJECT), _scan(_FOREIGN_SCAN, _FOREIGN_PROJECT)])
    await db.projects.update_one({"_id": _OWN_PROJECT}, {"$set": {"latest_scan_id": _OWN_SCAN}})
    await db.projects.update_one({"_id": _FOREIGN_PROJECT}, {"$set": {"latest_scan_id": _FOREIGN_SCAN}})
    await db.dependencies.insert_many(
        [
            _dependency("d-own", _OWN_SCAN, _OWN_PROJECT, _OWN_PACKAGE),
            _dependency("d-foreign", _FOREIGN_SCAN, _FOREIGN_PROJECT, _FOREIGN_PACKAGE),
        ]
    )
    await db.findings.insert_many(
        [
            _vulnerability("own", _OWN_SCAN, _OWN_PROJECT, _OWN_PACKAGE, "LOW"),
            _vulnerability("foreign", _FOREIGN_SCAN, _FOREIGN_PROJECT, _FOREIGN_PACKAGE, "CRITICAL"),
        ]
    )
    return owner_auth_headers_proj


@pytest.mark.asyncio
async def test_a_foreign_scan_id_is_not_found(client, seeded):
    resp = await client.get(
        f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree",
        params={"scan_id": _FOREIGN_SCAN},
        headers=seeded,
    )

    assert resp.status_code == 404
    assert resp.json() == {"detail": "No scan found for this project"}


@pytest.mark.asyncio
async def test_an_own_scan_id_returns_that_scans_graph(client, seeded):
    resp = await client.get(
        f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree",
        params={"scan_id": _OWN_SCAN},
        headers=seeded,
    )

    assert resp.status_code == 200, resp.text
    nodes = resp.json()["nodes"]
    assert [n["name"] for n in nodes] == [_OWN_PACKAGE]
    assert nodes[0]["findings_severity"]["low"] == 1


@pytest.mark.asyncio
async def test_rows_another_project_filed_under_the_scan_id_stay_out(client, db, seeded):
    await db.dependencies.insert_one(_dependency("d-stray", _OWN_SCAN, _FOREIGN_PROJECT, _FOREIGN_PACKAGE))
    await db.findings.insert_one(_vulnerability("stray", _OWN_SCAN, _FOREIGN_PROJECT, _OWN_PACKAGE, "CRITICAL"))

    resp = await client.get(f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree", headers=seeded)

    assert resp.status_code == 200, resp.text
    nodes = resp.json()["nodes"]
    assert [n["name"] for n in nodes] == [_OWN_PACKAGE]
    assert nodes[0]["findings_severity"]["critical"] == 0


@pytest.mark.asyncio
async def test_a_caller_outside_the_project_is_refused(client, seeded, owner_auth_headers_proj_p2):
    resp = await client.get(
        f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree",
        params={"scan_id": _OWN_SCAN},
        headers=owner_auth_headers_proj_p2,
    )

    assert resp.status_code == 403
    assert _OWN_PACKAGE not in resp.text


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_purl_less_operating_system_component_is_a_tree_node(client, db, seeded):
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"type": "container", "name": "registry.example/app", "bom-ref": "root"},
            "tools": [{"name": "syft", "version": "1.18.1"}],
        },
        "components": [{"type": "operating-system", "bom-ref": "os-debian", "name": "debian", "version": "12"}],
        "dependencies": [{"ref": "root", "dependsOn": ["os-debian"]}],
    }
    await store_scan_dependencies([parse_sbom(syft_sbom)], _OWN_PROJECT, _OWN_SCAN, DependencyRepository(db))

    resp = await client.get(f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree", headers=seeded)

    assert resp.status_code == 200, resp.text
    debian = next(n for n in resp.json()["nodes"] if n["name"] == "debian")
    assert debian["purl"] == ""


_TREE_PAYLOAD = ("description", "hashes", "properties", "cpes", "homepage", "license")


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_graph_is_built_without_the_payload_the_tree_does_not_show(client, db, seeded, monkeypatch):
    payload = {
        "description": "An own library.",
        "hashes": {"sha256": "abc"},
        "properties": {"syft:package:foundBy": "python-installed-package-cataloger"},
        "cpes": ["cpe:2.3:a:own:own-lib:1.0.0:*:*:*:*:*:*:*"],
        "homepage": "https://own.example/",
        "license": "MIT",
    }
    await db.dependencies.update_one({"_id": "d-own"}, {"$set": payload})
    rows: list = []
    build = tree_module._build_dependency_graph
    monkeypatch.setattr(
        tree_module, "_build_dependency_graph", lambda read, *rest: rows.extend(read) or build(read, *rest)
    )

    resp = await client.get(f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree", headers=seeded)

    assert resp.status_code == 200, resp.text
    [row] = rows
    assert {key: get_attr(row, key) for key in _TREE_PAYLOAD} == dict.fromkeys(_TREE_PAYLOAD)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_node_names_every_location_beside_how_many_there_are(client, db, seeded):
    locations = [f"/srv/app-{index}/requirements.txt" for index in range(5)]
    await db.dependencies.update_one({"_id": "d-own"}, {"$set": {"locations": locations}})
    await db.dependencies.insert_one(_dependency("d-bare", _OWN_SCAN, _OWN_PROJECT, "bare-lib"))

    resp = await client.get(f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree", headers=seeded)

    assert resp.status_code == 200, resp.text
    nodes = {node["name"]: node for node in resp.json()["nodes"]}
    assert (nodes[_OWN_PACKAGE]["locations"], nodes[_OWN_PACKAGE]["locations_total"]) == (locations, 5)
    assert (nodes["bare-lib"]["locations"], nodes["bare-lib"]["locations_total"]) == ([], 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(("population", "read"), [(4, 2), (2, 2), (1, 1)])
async def test_the_graph_reports_how_many_rows_it_read_of_what_the_scan_holds(
    client, db, seeded, monkeypatch, population, read
):
    monkeypatch.setattr(tree_module, "SCAN_DEPENDENCY_READ_LIMIT", 2)
    await db.dependencies.insert_many(
        [_dependency(f"d-{index}", _OWN_SCAN, _OWN_PROJECT, f"lib-{index}") for index in range(population - 1)]
    )

    resp = await client.get(f"/api/v1/analytics/projects/{_OWN_PROJECT}/dependency-tree", headers=seeded)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (len(body["nodes"]), body["dependencies_read"], body["dependencies_total"]) == (read, read, population)
