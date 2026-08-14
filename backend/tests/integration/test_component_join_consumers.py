"""Every consumer that joins a finding component against a dependency name.

The list was enumerated mechanically (see the task report): all `$lookup` stages from the
dependencies collection, all `$expr`/`$eq` name comparisons, every `dep_repo.aggregate`
pipeline, and every Python dict/set built from dependency documents. Each case below seeds
a Maven package the way prod stores it — dependency named `jackson-databind` with the group
in its own field, vulnerability finding carrying the full coordinate.
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

SCAN_ID = "scan-join"
QUALIFIED = "com.fasterxml.jackson.core:jackson-databind"
BARE = "jackson-databind"
VERSION = "2.20.2"


def _finding(_id: str, component: str, severity: str = "HIGH") -> dict:
    return {
        "_id": _id,
        "id": f"{component}:{VERSION}",
        "finding_id": f"{component}:{VERSION}",
        "scan_id": SCAN_ID,
        "project_id": "p",
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": VERSION,
        "description": "",
        "scanners": ["trivy"],
        "waived": False,
        "scan_created_at": datetime.now(timezone.utc),
        "details": {
            "fixed_version": "2.20.3",
            "vulnerabilities": [{"id": "CVE-2026-1", "severity": severity, "fixed_version": "2.20.3"}],
        },
    }


def _dependency(_id: str = "d1", name: str = BARE, direct: bool = True) -> dict:
    return {
        "_id": _id,
        "scan_id": SCAN_ID,
        "project_id": "p",
        "name": name,
        "version": VERSION,
        "group": "com.fasterxml.jackson.core",
        "purl": f"pkg:maven/com.fasterxml.jackson.core/{name}@{VERSION}",
        "type": "maven",
        "direct": direct,
        "direct_inferred": False,
        "source_type": "file-system",
        "source_target": "app.jar",
        "parent_components": [],
    }


@pytest_asyncio.fixture
async def seeded(db, owner_auth_headers_proj):
    await db.scans.insert_one(
        {
            "_id": SCAN_ID,
            "project_id": "p",
            "status": "completed",
            "branch": "main",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.projects.update_one({"_id": "p"}, {"$set": {"latest_scan_id": SCAN_ID}})
    await db.findings.insert_one(_finding("f1", QUALIFIED))
    await db.dependencies.insert_one(_dependency())
    return owner_auth_headers_proj


@pytest.mark.asyncio
async def test_scan_findings_table_still_carries_dependency_info(client, db, seeded):
    """projects.py $lookup — purl/direct/origin drive the main findings table."""
    resp = await client.get(f"/api/v1/projects/scans/{SCAN_ID}/findings", headers=seeded)
    assert resp.status_code == 200, resp.text
    row = resp.json()["items"][0]
    assert row["purl"] == f"pkg:maven/com.fasterxml.jackson.core/{BARE}@{VERSION}"
    assert row["direct"] is True
    assert row["source_type"] == "file-system"


@pytest.mark.asyncio
async def test_scan_findings_lookup_prefers_the_exact_spelling(client, db, seeded):
    """A bare-named finding must take its own row, not a same-artifact sibling's."""
    await db.dependencies.insert_one(_dependency("d2", name=QUALIFIED, direct=False))
    await db.findings.insert_one(_finding("f2", BARE))

    resp = await client.get(f"/api/v1/projects/scans/{SCAN_ID}/findings", headers=seeded)
    assert resp.status_code == 200, resp.text
    by_component = {r["component"]: r for r in resp.json()["items"]}
    assert by_component[BARE]["direct"] is True
    assert by_component[QUALIFIED]["direct"] is False


@pytest.mark.asyncio
async def test_hotspots_report_the_dependency_type(client, db, seeded):
    """risk.py dep_type_map — the hotspot type comes from the inventory."""
    resp = await client.get("/api/v1/analytics/hotspots", headers=seeded)
    assert resp.status_code == 200, resp.text
    assert resp.json()[0]["type"] == "maven"


@pytest.mark.asyncio
async def test_dependency_search_vulnerability_filter_matches(client, db, seeded):
    """search.py vuln_status_map — has_vulnerabilities=true must find the Maven dependency."""
    resp = await client.get(
        "/api/v1/analytics/search",
        params={"q": "jackson", "has_vulnerabilities": "true"},
        headers=seeded,
    )
    assert resp.status_code == 200, resp.text
    assert [item["package"] for item in resp.json()["items"]] == [BARE]


@pytest.mark.asyncio
async def test_findings_export_row_carries_purl_and_direct(db, seeded):
    """inventory/findings_export.py _dependency_lookup."""
    from app.models.project import Scan
    from app.services.inventory.findings_export import iter_findings_rows

    scan = Scan(**(await db.scans.find_one({"_id": SCAN_ID})))
    rows = [row async for row in iter_findings_rows(db, [scan])]

    assert rows[0]["purl"] == f"pkg:maven/com.fasterxml.jackson.core/{BARE}@{VERSION}"
    assert rows[0]["direct"] is True


@pytest.mark.asyncio
async def test_remediation_plan_marks_the_package_direct(db, seeded):
    """chat/tools/registry.py dep_index — drives is_direct, ecosystem and the plan ordering."""
    from app.models.user import User
    from app.services.chat.tools.registry import ChatToolRegistry

    await db.findings.update_one({"_id": "f1"}, {"$set": {"severity": "CRITICAL"}})
    user = User(id="ownerp", username="ownerp", email="o@example.com", permissions=["*"])
    plan = await ChatToolRegistry().execute_tool("generate_remediation_plan", {"project_id": "p"}, user, db)

    step = plan["plan"][0]
    assert step["is_direct"] is True
    assert step["ecosystem"] == "maven"


@pytest.mark.asyncio
async def test_dependency_metadata_resolves_a_hotspot_component(client, db, seeded):
    """The Hotspots and Impact tabs pass a finding-derived component straight to this endpoint.

    frontend/src/pages/Analytics.tsx:99,107 hand `result.component` / `hotspot.component` to
    the modal, which calls /dependency-metadata and /component-findings side by side, so an
    unresolvable dependency query leaves a populated findings list next to an empty panel.
    """
    resp = await client.get("/api/v1/analytics/dependency-metadata", params={"component": QUALIFIED}, headers=seeded)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body is not None
    assert body["name"] == BARE
    assert body["purl"] == f"pkg:maven/com.fasterxml.jackson.core/{BARE}@{VERSION}"
    assert body["total_vulnerability_count"] == 1


@pytest.mark.asyncio
async def test_dependency_metadata_does_not_guess_an_ambiguous_hotspot_component(client, db, seeded):
    """Two inventory packages end in 'core'; a bare hotspot component must not pick one."""
    for idx, name in enumerate(["@angular/core", "@messageformat/core"]):
        await db.dependencies.insert_one(_dependency(f"amb{idx}", name=name))

    resp = await client.get("/api/v1/analytics/dependency-metadata", params={"component": "core"}, headers=seeded)
    assert resp.status_code == 200, resp.text
    assert resp.json() is None


@pytest.mark.asyncio
async def test_hotspot_type_resolves_for_a_mixed_case_maven_artifact(client, db, seeded):
    """Inventory names preserve case; lowercased candidates never match HikariCP."""
    await db.dependencies.insert_one(_dependency("d-hik", name="HikariCP"))
    await db.findings.insert_one(_finding("f-hik", "com.zaxxer:HikariCP"))

    resp = await client.get("/api/v1/analytics/hotspots", headers=seeded)
    assert resp.status_code == 200, resp.text
    types = {row["component"]: row["type"] for row in resp.json()}
    assert types["com.zaxxer:HikariCP"] == "maven"


@pytest.mark.asyncio
async def test_find_component_usage_accepts_a_qualified_component(db, seeded):
    """chat/MCP: the caller quotes a finding's component, the inventory holds the bare name."""
    from app.models.user import User
    from app.services.chat.tools.registry import ChatToolRegistry

    user = User(id="ownerp", username="ownerp", email="o@example.com", permissions=["*"])
    result = await ChatToolRegistry().execute_tool("find_component_usage", {"component_name": QUALIFIED}, user, db)

    assert [m["component"] for m in result["matches"]] == [BARE]
