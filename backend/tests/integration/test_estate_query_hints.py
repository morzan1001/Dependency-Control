"""Reads over every head scan name their index, so the planner does not trial-run each scan_id index first."""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.core.init_db import create_indexes
from app.core.permissions import Permissions
from tests.helpers.auth import bearer_headers
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_SCAN_ID = "head-p"
_COMPONENT = "lodash"
# Rows of an older, non-head scan: a read that loses its scan_id bound walks past all of them.
_DECOYS = 50


@pytest_asyncio.fixture
async def estate(db, owner_auth_headers_proj):
    await create_indexes(db)
    await db.scans.insert_one(
        {"_id": _SCAN_ID, "project_id": "p", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": _SCAN_ID}})
    await db.dependencies.insert_one(
        {
            "_id": "dep-lodash",
            "scan_id": _SCAN_ID,
            "project_id": "p",
            "name": _COMPONENT,
            "version": "4.17.15",
            "purl": f"pkg:npm/{_COMPONENT}@4.17.15",
            "type": "npm",
            "direct": True,
            "parent_components": [],
        }
    )
    await db.findings.insert_one(
        {
            "_id": "finding-lodash",
            "id": "CVE-2026-0001",
            "finding_id": "CVE-2026-0001",
            "description": "",
            "scanners": ["trivy"],
            "scan_id": _SCAN_ID,
            "project_id": "p",
            "type": "vulnerability",
            "severity": "HIGH",
            "component": _COMPONENT,
            "version": "4.17.15",
            "waived": False,
            "scan_created_at": datetime.now(timezone.utc),
            "details": {"vulnerabilities": [{"id": "CVE-2026-0001", "severity": "HIGH", "aliases": []}]},
        }
    )
    old = [f"{_COMPONENT}@4.0.{i}" for i in range(_DECOYS)]
    await db.dependencies.insert_many(
        [
            {
                "_id": f"dep-old-{i}",
                "scan_id": "old-p",
                "project_id": "p",
                "name": _COMPONENT,
                "version": version.split("@")[1],
                "purl": f"pkg:npm/{version}",
                "type": "npm",
                "direct": True,
                "parent_components": [],
            }
            for i, version in enumerate(old)
        ]
    )
    await db.findings.insert_many(
        [
            {
                "_id": f"finding-old-{i}",
                "id": "CVE-2026-0001",
                "finding_id": "CVE-2026-0001",
                "description": "",
                "scanners": ["trivy"],
                "scan_id": "old-p",
                "project_id": "p",
                "type": "vulnerability",
                "severity": "HIGH",
                "component": _COMPONENT,
                "version": version.split("@")[1],
                "waived": False,
                "scan_created_at": datetime.now(timezone.utc),
                "details": {"vulnerabilities": [{"id": "CVE-2026-0001", "severity": "HIGH", "aliases": []}]},
            }
            for i, version in enumerate(old)
        ]
    )
    return owner_auth_headers_proj


async def _profiled(db, request):
    resp, entries = await profiled(db, request)
    assert resp.status_code == 200, resp.text
    return resp, entries


def _plans(entries, collection, command):
    return [
        (e["planSummary"], e["keysExamined"] < _DECOYS)
        for e in entries
        if e["ns"].endswith(f".{collection}")
        and command in e["command"]
        and "hint" in e["command"]
        and "planSummary" in e
    ]


async def test_top_dependencies_count_vulnerabilities_off_the_scan_type_index(client, db, estate):
    resp, entries = await _profiled(db, client.get("/api/v1/analytics/dependencies/top", headers=estate))

    assert [(d["name"], d["vulnerability_count"]) for d in resp.json()] == [(_COMPONENT, 1)]
    assert _plans(entries, "findings", "aggregate") == [("IXSCAN { scan_id: 1, type: 1 }", True)]


async def test_component_findings_resolve_spellings_off_the_scan_component_index(client, db, estate):
    resp, entries = await _profiled(
        db, client.get("/api/v1/analytics/component-findings", params={"component": _COMPONENT}, headers=estate)
    )

    assert [f["finding_id"] for f in resp.json()] == ["CVE-2026-0001"]
    assert _plans(entries, "findings", "aggregate") == [("IXSCAN { scan_id: 1, component: 1, version: 1 }", True)]


async def test_package_suggestions_match_names_off_the_scan_package_index(client, db, estate):
    headers = bearer_headers("broadcaster", [Permissions.NOTIFICATIONS_BROADCAST])

    resp, entries = await _profiled(
        db, client.get("/api/v1/notifications/packages/suggest", params={"q": "lod"}, headers=headers)
    )

    assert resp.json()["names"] == [_COMPONENT]
    plan = _plans(entries, "dependencies", "aggregate")
    assert plan == [("IXSCAN { scan_id: 1, name: 1, version: 1, purl: 1 }", True)]


async def test_an_advisory_finds_its_projects_off_the_scan_package_index(client, db, estate):
    headers = bearer_headers("broadcaster", [Permissions.NOTIFICATIONS_BROADCAST])
    advisory = {
        "type": "advisory",
        "target_type": "advisory",
        "packages": [{"name": _COMPONENT}],
        "subject": "s",
        "message": "m",
        "channels": ["email"],
        "dry_run": True,
    }

    resp, entries = await _profiled(db, client.post("/api/v1/notifications/broadcast", json=advisory, headers=headers))

    assert resp.json()["project_count"] == 1
    assert _plans(entries, "dependencies", "find") == [("IXSCAN { scan_id: 1, name: 1, version: 1, purl: 1 }", True)]


async def test_vulnerability_search_counts_and_pages_off_the_scan_type_index(client, db, estate):
    resp, entries = await _profiled(
        db, client.get("/api/v1/analytics/vulnerability-search", params={"q": "CVE-2026-0001"}, headers=estate)
    )

    assert [item["vulnerability_id"] for item in resp.json()["items"]] == ["CVE-2026-0001"]
    assert _plans(entries, "findings", "aggregate") == [("IXSCAN { scan_id: 1, type: 1 }", True)] * 2


async def test_the_vulnerability_filter_reads_only_the_findings_of_the_matching_dependencies_scans(client, db, estate):
    from app.models.project import Project, ProjectMember

    other = Project(id="p2", name="project-p2", members=[ProjectMember(user_id="ownerp", role="admin")])
    await db.projects.insert_one({**other.model_dump(by_alias=True), "latest_scan_id": "head-p2"})
    await db.scans.insert_one(
        {"_id": "head-p2", "project_id": "p2", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    finding = await db.findings.find_one({"_id": "finding-lodash"})
    await db.findings.insert_many(
        [
            {**finding, "_id": f"finding-p2-{i}", "scan_id": "head-p2", "project_id": "p2", "component": f"lib-{i}"}
            for i in range(_DECOYS)
        ]
    )

    resp, entries = await _profiled(
        db,
        client.get("/api/v1/analytics/search", params={"q": _COMPONENT, "has_vulnerabilities": "true"}, headers=estate),
    )

    assert [item["package"] for item in resp.json()["items"]] == [_COMPONENT]
    assert _plans(entries, "findings", "aggregate") == [("IXSCAN { scan_id: 1, type: 1 }", True)]
