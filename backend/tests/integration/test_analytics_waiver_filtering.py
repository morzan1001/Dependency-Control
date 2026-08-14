"""Analytics surfaces must agree with the scan stats on what is waived.

``calculate_comprehensive_stats`` and the finding repository count only ``waived != True``.
The impact/hotspot rankings, the dependency-tree severity overlay and the component-finding
list ignored the flag, so a waived CVE kept driving a component's rank and fix_impact_score
while it had already disappeared from the severity tiles of the same scan.
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

SCAN_ID = "scan-waived"


def _vuln(_id: str, component: str, severity: str, waived: bool) -> dict:
    return {
        "_id": _id,
        "id": f"{component}:1.0.0",
        "finding_id": f"{component}:1.0.0",
        "description": "",
        "scanners": ["trivy"],
        "scan_id": SCAN_ID,
        "project_id": "p",
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": "1.0.0",
        "waived": waived,
        "waiver_reason": "accepted risk" if waived else None,
        "scan_created_at": datetime.now(timezone.utc),
        "details": {
            "vulnerabilities": [{"id": f"CVE-2026-{_id}", "severity": severity, "waived": waived, "aliases": []}]
        },
    }


@pytest_asyncio.fixture
async def seeded(db, owner_auth_headers_proj):
    await db.scans.insert_one(
        {
            "_id": SCAN_ID,
            "project_id": "p",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": SCAN_ID}})
    await db.findings.insert_one(_vuln("live", "left-pad", "HIGH", waived=False))
    await db.findings.insert_one(_vuln("hidden", "waived-pkg", "CRITICAL", waived=True))
    await db.dependencies.insert_one(
        {
            "_id": "d1",
            "scan_id": SCAN_ID,
            "project_id": "p",
            "name": "waived-pkg",
            "version": "1.0.0",
            "purl": "pkg:npm/waived-pkg@1.0.0",
            "type": "npm",
            "direct": True,
            "parent_components": [],
        }
    )
    return owner_auth_headers_proj


@pytest.mark.asyncio
async def test_impact_ranking_skips_waived_findings(client, seeded):
    resp = await client.get("/api/v1/analytics/impact", headers=seeded)
    assert resp.status_code == 200, resp.text
    assert [row["component"] for row in resp.json()] == ["left-pad"]


@pytest.mark.asyncio
async def test_hotspots_skip_waived_findings(client, seeded):
    resp = await client.get("/api/v1/analytics/hotspots", headers=seeded)
    assert resp.status_code == 200, resp.text
    assert [row["component"] for row in resp.json()] == ["left-pad"]


@pytest.mark.asyncio
async def test_dependency_tree_overlay_skips_waived_findings(client, seeded):
    resp = await client.get("/api/v1/analytics/projects/p/dependency-tree", headers=seeded)
    assert resp.status_code == 200, resp.text
    node = resp.json()["nodes"][0]
    assert node["name"] == "waived-pkg"
    assert node["findings_count"] == 0
    assert node["has_findings"] is False


@pytest.mark.asyncio
async def test_component_findings_skip_waived_findings(client, seeded):
    resp = await client.get("/api/v1/analytics/component-findings", params={"component": "waived-pkg"}, headers=seeded)
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


@pytest.mark.asyncio
async def test_dependency_metadata_skips_waived_findings(client, seeded):
    resp = await client.get("/api/v1/analytics/dependency-metadata", params={"component": "waived-pkg"}, headers=seeded)
    assert resp.status_code == 200, resp.text
    assert resp.json()["total_finding_count"] == 0
    assert resp.json()["total_vulnerability_count"] == 0


@pytest.mark.asyncio
async def test_dependency_metadata_counts_a_requalified_finding(client, db, seeded):
    """The dependency is inventoried bare; its vulnerability carries the Maven coordinate."""
    await db.dependencies.insert_one(
        {
            "_id": "d2",
            "scan_id": SCAN_ID,
            "project_id": "p",
            "name": "jackson-databind",
            "version": "2.20.2",
            "group": "com.fasterxml.jackson.core",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.20.2",
            "type": "library",
            "direct": True,
            "parent_components": [],
        }
    )
    await db.findings.insert_one(
        _vuln("qualified", "com.fasterxml.jackson.core:jackson-databind", "HIGH", waived=False)
    )

    resp = await client.get(
        "/api/v1/analytics/dependency-metadata", params={"component": "jackson-databind"}, headers=seeded
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["total_vulnerability_count"] == 1


@pytest.mark.asyncio
async def test_component_findings_blanks_on_an_ambiguous_bare_name(client, db, seeded):
    """Two packages end in 'core'; the tree overlay blanks, so this must not union them."""
    for idx, component in enumerate(["@angular/core", "@messageformat/core"]):
        await db.findings.insert_one(_vuln(f"amb{idx}", component, "HIGH", waived=False))

    resp = await client.get("/api/v1/analytics/component-findings", params={"component": "core"}, headers=seeded)
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


@pytest.mark.asyncio
async def test_component_findings_still_resolve_an_unambiguous_bare_name(client, db, seeded):
    await db.findings.insert_one(_vuln("single", "com.fasterxml.jackson.core:jackson-databind", "HIGH", waived=False))

    resp = await client.get(
        "/api/v1/analytics/component-findings", params={"component": "jackson-databind"}, headers=seeded
    )
    assert resp.status_code == 200, resp.text
    assert [f["component"] for f in resp.json()] == ["com.fasterxml.jackson.core:jackson-databind"]


@pytest.mark.asyncio
async def test_dependency_metadata_blanks_on_an_ambiguous_bare_name(client, db, seeded):
    """Same policy as the findings list rendered beside it in the modal."""
    await db.dependencies.insert_one(
        {
            "_id": "d3",
            "scan_id": SCAN_ID,
            "project_id": "p",
            "name": "core",
            "version": "1.0.0",
            "purl": "pkg:npm/%40angular/core@1.0.0",
            "type": "npm",
            "direct": True,
            "parent_components": [],
        }
    )
    for idx, component in enumerate(["@angular/core", "@messageformat/core"]):
        await db.findings.insert_one(_vuln(f"dm{idx}", component, "HIGH", waived=False))

    resp = await client.get("/api/v1/analytics/dependency-metadata", params={"component": "core"}, headers=seeded)
    assert resp.status_code == 200, resp.text
    assert resp.json()["total_vulnerability_count"] == 0
