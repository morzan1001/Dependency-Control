"""Every analytics surface counts a component's vulnerabilities the same way: distinct live CVEs.

A vulnerability finding is one document per component version holding every advisory, so a
count of documents says how many versions are affected, not how many vulnerabilities there are.
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

SCAN_ID = "scan-cve-counts"
COMPONENT = "lodash"


def _advisory(cve: str, severity: str, waived: bool = False) -> dict:
    return {"id": cve, "severity": severity, "waived": waived, "aliases": []}


def _finding(advisories: list[dict], component: str = COMPONENT) -> dict:
    return {
        "_id": f"finding-{component}",
        "id": f"{component}:4.17.15",
        "finding_id": f"{component}:4.17.15",
        "description": "",
        "scanners": ["trivy"],
        "scan_id": SCAN_ID,
        "project_id": "p",
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": component,
        "version": "4.17.15",
        "waived": False,
        "scan_created_at": datetime.now(timezone.utc),
        "details": {"vulnerabilities": advisories},
    }


@pytest_asyncio.fixture
async def scanned(db, owner_auth_headers_proj):
    await db.scans.insert_one(
        {"_id": SCAN_ID, "project_id": "p", "status": "completed", "created_at": datetime.now(timezone.utc)}
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": SCAN_ID}})
    for component in (COMPONENT, "mystery-lib"):
        await db.dependencies.insert_one(
            {
                "_id": f"dep-{component}",
                "scan_id": SCAN_ID,
                "project_id": "p",
                "name": component,
                "version": "4.17.15",
                "purl": f"pkg:npm/{component}@4.17.15",
                "type": "npm",
                "direct": True,
                "parent_components": [],
            }
        )
    return owner_auth_headers_proj


async def _counts(client, headers, component: str = COMPONENT) -> dict:
    tree = await client.get("/api/v1/analytics/projects/p/dependency-tree", headers=headers)
    hotspots = await client.get("/api/v1/analytics/hotspots", headers=headers)
    top = await client.get("/api/v1/analytics/dependencies/top", headers=headers)
    metadata = await client.get(
        "/api/v1/analytics/dependency-metadata", params={"component": component}, headers=headers
    )
    for resp in (tree, hotspots, top, metadata):
        assert resp.status_code == 200, resp.text
    node = next(n for n in tree.json()["nodes"] if n["name"] == component)
    hotspot = next(h for h in hotspots.json() if h["component"] == component)
    usage = next(d for d in top.json() if d["name"] == component)
    return {
        "tree": node["findings_count"],
        "tree_severity": node["findings_severity"],
        "hotspot": hotspot["finding_count"],
        "hotspot_cves": hotspot["cve_count"],
        "top": usage["vulnerability_count"],
        "metadata": metadata.json()["total_vulnerability_count"],
    }


@pytest.mark.asyncio
async def test_every_surface_counts_the_cves_of_one_component_version(client, db, scanned):
    advisories = [
        _advisory("CVE-2026-0001", "CRITICAL"),
        _advisory("CVE-2026-0002", "HIGH"),
        _advisory("CVE-2026-0003", "HIGH"),
        _advisory("CVE-2026-0004", "MEDIUM"),
    ]
    await db.findings.insert_one(_finding(advisories))

    counts = await _counts(client, scanned)

    assert {k: v for k, v in counts.items() if k != "tree_severity"} == dict.fromkeys(
        ("tree", "hotspot", "hotspot_cves", "top", "metadata"), 4
    )
    assert (counts["tree_severity"]["critical"], counts["tree_severity"]["high"]) == (1, 2)


@pytest.mark.asyncio
async def test_a_cve_waived_on_its_own_is_counted_nowhere(client, db, scanned):
    advisories = [_advisory("CVE-2026-0001", "CRITICAL", waived=True), _advisory("CVE-2026-0002", "LOW")]
    await db.findings.insert_one(_finding(advisories))

    counts = await _counts(client, scanned)

    assert (counts["tree"], counts["hotspot"], counts["hotspot_cves"], counts["top"], counts["metadata"]) == (
        1,
        1,
        1,
        1,
        1,
    )
    assert counts["tree_severity"]["critical"] == 0


@pytest.mark.asyncio
async def test_a_cve_of_unknown_severity_still_counts(client, db, scanned):
    await db.findings.insert_one(_finding([_advisory("CVE-2026-0009", "UNKNOWN")], component="mystery-lib"))

    counts = await _counts(client, scanned, component="mystery-lib")

    assert (counts["tree"], counts["hotspot"], counts["top"], counts["metadata"]) == (1, 1, 1, 1)
    assert counts["tree_severity"]["unknown"] == 1
