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

from app.repositories.dependencies import DependencyRepository
from app.services.dependency_store import store_scan_dependencies
from app.services.sbom_parser import parse_sbom

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
    """risk.py hotspot type — the type comes from the inventory."""
    resp = await client.get("/api/v1/analytics/hotspots", headers=seeded)
    assert resp.status_code == 200, resp.text
    assert resp.json()[0]["type"] == "maven"


@pytest.mark.asyncio
async def test_dependency_search_vulnerability_filter_matches(client, db, seeded):
    """search.py vulnerability filter — has_vulnerabilities=true must find the Maven dependency."""
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
    from app.core.permissions import Permissions
    from app.models.user import User
    from app.services.chat.tools.registry import ChatToolRegistry

    await db.findings.update_one({"_id": "f1"}, {"$set": {"severity": "CRITICAL"}})
    user = User(
        id="ownerp",
        username="ownerp",
        email="o@example.com",
        permissions=[Permissions.PROJECT_READ, Permissions.ANALYTICS_READ],
    )
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
    from app.core.permissions import Permissions
    from app.models.user import User
    from app.services.chat.tools.registry import ChatToolRegistry

    user = User(
        id="ownerp",
        username="ownerp",
        email="o@example.com",
        permissions=[Permissions.PROJECT_READ, Permissions.ANALYTICS_READ],
    )
    result = await ChatToolRegistry().execute_tool("find_component_usage", {"component_name": QUALIFIED}, user, db)

    assert [m["component"] for m in result["matches"]] == [BARE]


@pytest.mark.asyncio
async def test_findings_export_prefers_the_direct_row_on_a_name_version_collision(db, seeded):
    """Multi-SBOM scans store the same name@version under two purl spellings (bare and
    ?type=jar). On 60 sampled production multi-SBOM scans 2,452 of 11,882 dependency docs
    sit in such groups and 1,635 of the groups disagree on `direct`, so keeping whichever
    document the cursor yielded last made the exported column a coin flip."""
    from app.models.project import Scan
    from app.services.inventory.findings_export import iter_findings_rows

    # Inserted after the seeded direct row so a last-wins index would pick the transitive one.
    transitive = _dependency("d-jar", direct=False)
    transitive["purl"] = f"pkg:maven/com.fasterxml.jackson.core/{BARE}@{VERSION}?type=jar"
    await db.dependencies.insert_one(transitive)

    scan = Scan(**(await db.scans.find_one({"_id": SCAN_ID})))
    rows = [row async for row in iter_findings_rows(db, [scan])]

    assert rows[0]["direct"] is True
    assert rows[0]["purl"] == f"pkg:maven/com.fasterxml.jackson.core/{BARE}@{VERSION}"


@pytest.mark.asyncio
async def test_findings_export_prefers_the_direct_row_stored_after_the_transitive_one(db, seeded):
    """The sibling case above seeds the direct row first, where first-wins looks like the
    tie-break; only the reverse insertion order tells the two apart."""
    from app.models.project import Scan
    from app.services.inventory.findings_export import iter_findings_rows

    transitive = _dependency("d-netty-jar", name="netty-common", direct=False)
    transitive["group"] = "io.netty"
    transitive["purl"] = f"pkg:maven/io.netty/netty-common@{VERSION}?type=jar"
    await db.dependencies.insert_one(transitive)
    declared = _dependency("d-netty", name="netty-common")
    declared["group"] = "io.netty"
    declared["purl"] = f"pkg:maven/io.netty/netty-common@{VERSION}"
    await db.dependencies.insert_one(declared)
    await db.findings.insert_one(_finding("f-netty", "io.netty:netty-common"))

    scan = Scan(**(await db.scans.find_one({"_id": SCAN_ID})))
    rows = {row["component"]: row async for row in iter_findings_rows(db, [scan])}

    assert rows["io.netty:netty-common"]["direct"] is True
    assert rows["io.netty:netty-common"]["purl"] == f"pkg:maven/io.netty/netty-common@{VERSION}"


@pytest.mark.asyncio
async def test_inferred_direct_is_reported_the_same_way_by_both_tools(db, seeded):
    """generate_remediation_plan treated an inferred-direct package as transitive while
    find_component_usage treated it as direct (and never read the flag). Both now report
    `direct_confidence` so the collapse is the reader's choice, not the tool's."""
    from app.core.permissions import Permissions
    from app.models.user import User
    from app.services.chat.tools.registry import ChatToolRegistry

    await db.dependencies.update_one({"_id": "d1"}, {"$set": {"direct_inferred": True}})
    await db.findings.update_one({"_id": "f1"}, {"$set": {"severity": "CRITICAL"}})
    user = User(
        id="ownerp",
        username="ownerp",
        email="o@example.com",
        permissions=[Permissions.PROJECT_READ, Permissions.ANALYTICS_READ],
    )
    registry = ChatToolRegistry()

    plan = await registry.execute_tool("generate_remediation_plan", {"project_id": "p"}, user, db)
    usage = await registry.execute_tool("find_component_usage", {"component_name": BARE}, user, db)

    assert plan["plan"][0]["direct_confidence"] == "inferred"
    assert plan["plan"][0]["is_direct"] is True
    assert usage["matches"][0]["direct_confidence"] == "inferred"
    assert usage["matches"][0]["direct_dependency"] is True


@pytest.mark.asyncio
async def test_declared_direct_still_outranks_inferred_direct_in_the_plan(db, seeded):
    """The old `and not direct_inferred` collapse existed to deprioritise guesses; that
    intent moves into the ordering instead of into the reported flag."""
    from app.core.permissions import Permissions
    from app.models.user import User
    from app.services.chat.tools.registry import ChatToolRegistry

    await db.dependencies.update_one({"_id": "d1"}, {"$set": {"direct_inferred": True}})
    await db.findings.update_one({"_id": "f1"}, {"$set": {"severity": "CRITICAL"}})
    await db.findings.insert_one(_finding("f2", "netty-common", severity="CRITICAL"))
    declared = _dependency("d3", name="netty-common")
    declared["group"] = "io.netty"
    declared["purl"] = f"pkg:maven/io.netty/netty-common@{VERSION}"
    await db.dependencies.insert_one(declared)

    user = User(
        id="ownerp",
        username="ownerp",
        email="o@example.com",
        permissions=[Permissions.PROJECT_READ, Permissions.ANALYTICS_READ],
    )
    plan = await ChatToolRegistry().execute_tool("generate_remediation_plan", {"project_id": "p"}, user, db)

    assert [s["direct_confidence"] for s in plan["plan"]] == ["declared", "inferred"]


@pytest.mark.asyncio
async def test_a_declared_direct_row_outranks_a_later_inferred_row_of_the_package(db, seeded):
    from app.core.permissions import Permissions
    from app.models.user import User
    from app.services.chat.tools.registry import ChatToolRegistry

    inferred = _dependency("d-inferred")
    inferred.update(version="2.8.0", direct_inferred=True, purl=f"pkg:maven/com.fasterxml.jackson.core/{BARE}@2.8.0")
    await db.dependencies.insert_one(inferred)
    user = User(
        id="ownerp",
        username="ownerp",
        email="o@example.com",
        permissions=[Permissions.PROJECT_READ, Permissions.ANALYTICS_READ],
    )
    plan = await ChatToolRegistry().execute_tool("generate_remediation_plan", {"project_id": "p"}, user, db)

    assert plan["plan"][0]["direct_confidence"] == "declared"


async def _analytics(client, path: str, headers: dict, **params):
    resp = await client.get(f"/api/v1/analytics/{path}", params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _store_cyclonedx(db, *components: dict) -> None:
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": list(components)}
    await store_scan_dependencies([parse_sbom(sbom)], "p", SCAN_ID, DependencyRepository(db))


@pytest.mark.asyncio
async def test_a_qualified_hotspot_lists_the_findings_stored_under_the_bare_name(client, db, seeded):
    """Outdated and license findings keep the SBOM's bare name; the vulnerability carries the coordinate."""
    for idx, finding_type in enumerate(["outdated", "license"]):
        await db.findings.insert_one({**_finding(f"bare{idx}", BARE), "type": finding_type, "id": f"{finding_type}-x"})

    findings = await _analytics(client, "component-findings", seeded, component=QUALIFIED)
    metadata = await _analytics(client, "dependency-metadata", seeded, component=QUALIFIED)

    assert sorted(f["type"] for f in findings) == ["license", "outdated", "vulnerability"]
    assert metadata["total_finding_count"] == len(findings)
    assert metadata["total_vulnerability_count"] == 1


@pytest.mark.asyncio
async def test_both_panels_decide_a_bare_name_from_the_same_version_scoped_evidence(client, db, seeded):
    await db.findings.insert_one({**_finding("core-a", "com.a:core"), "version": "1.0"})
    await db.findings.insert_one({**_finding("core-b", "com.b:core"), "version": "2.0"})
    await db.dependencies.insert_one({**_dependency("dep-core", name="core"), "version": "1.0"})

    findings = await _analytics(client, "component-findings", seeded, component="core", version="1.0")
    metadata = await _analytics(client, "dependency-metadata", seeded, component="core", version="1.0")

    assert [f["component"] for f in findings] == ["com.a:core"]
    assert metadata["total_finding_count"] == len(findings)


@pytest.mark.asyncio
async def test_a_bare_name_shared_by_two_packages_resolves_to_neither(client, db, seeded):
    await db.findings.insert_one({**_finding("core-a", "com.a:core"), "version": "1.0"})
    await db.findings.insert_one({**_finding("core-b", "com.b:core"), "version": "1.0"})
    await db.dependencies.insert_one({**_dependency("dep-core", name="core"), "version": "1.0"})

    findings = await _analytics(client, "component-findings", seeded, component="core")
    metadata = await _analytics(client, "dependency-metadata", seeded, component="core")

    assert findings == []
    assert metadata["total_finding_count"] == 0


def _maven(_id: str, group: str, name: str = "core", version: str = "1.0", **extra) -> dict:
    return {
        **_dependency(_id, name=name),
        "group": group,
        "version": version,
        "purl": f"pkg:maven/{group}/{name}@{version}",
        **extra,
    }


async def _add_project(db, project_id: str, scan_id: str, members: list | None = None) -> None:
    now = datetime.now(timezone.utc)
    await db.scans.insert_one(
        {"_id": scan_id, "project_id": project_id, "status": "completed", "branch": "main", "created_at": now}
    )
    members = [{"user_id": "ownerp", "role": "admin"}] if members is None else members
    await db.projects.insert_one({"_id": project_id, "name": project_id, "latest_scan_id": scan_id, "members": members})


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_qualified_component_reads_only_its_own_group_s_metadata(client, db, seeded):
    await db.dependencies.insert_one(_maven("zxing", "com.google.zxing", license="Apache-2.0"))
    await db.dependencies.insert_one(_maven("jdt", "org.eclipse.jdt", license="EPL-2.0"))

    metadata = await _analytics(client, "dependency-metadata", seeded, component="org.eclipse.jdt:core")
    bare = await _analytics(client, "dependency-metadata", seeded, component="core")

    assert (metadata["purl"], metadata["license"]) == ("pkg:maven/org.eclipse.jdt/core@1.0", "EPL-2.0")
    assert bare is None


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_qualified_component_reads_purl_less_rows_by_their_group(client, db, seeded):
    await db.dependencies.insert_one({**_maven("zxing", "com.google.zxing", license="Apache-2.0"), "purl": None})
    await db.dependencies.insert_one({**_maven("jdt", "org.eclipse.jdt", license="EPL-2.0"), "purl": None})

    metadata = await _analytics(client, "dependency-metadata", seeded, component="org.eclipse.jdt:core")

    assert (metadata["group"], metadata["license"]) == ("org.eclipse.jdt", "EPL-2.0")


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_metadata_without_a_version_describes_the_most_used_version(client, db, seeded):
    group = "org.example"
    await _add_project(db, "p2", "scan-p2")
    await _add_project(db, "p3", "scan-p3")
    await db.dependencies.insert_one(_maven("old", group, name="lib", version="1.0"))
    for project_id in ("p2", "p3"):
        await db.dependencies.insert_one(
            {
                **_maven(f"new-{project_id}", group, name="lib", version="2.0"),
                "project_id": project_id,
                "scan_id": f"scan-{project_id}",
            }
        )

    metadata = await _analytics(client, "dependency-metadata", seeded, component="lib")

    assert (metadata["version"], metadata["purl"]) == ("2.0", f"pkg:maven/{group}/lib@2.0")
    assert metadata["versions"] == ["2.0", "1.0"]
    assert metadata["project_count"] == 3


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_hotspot_type_comes_from_the_hotspot_s_own_scans_and_version(client, db, seeded):
    await _add_project(db, "elsewhere", "scan-elsewhere", members=[])
    await db.dependencies.insert_one(
        {
            **_dependency("apk-other", name="openssl"),
            "type": "apk",
            "purl": None,
            "scan_id": "scan-elsewhere",
            "project_id": "elsewhere",
        }
    )
    await db.dependencies.insert_one({**_dependency("deb", name="openssl"), "type": "deb", "purl": None})
    await db.dependencies.insert_one({**_dependency("zlib-deb", name="zlib"), "type": "deb", "purl": None})
    await db.dependencies.insert_one({**_dependency("zlib-apk", name="zlib"), "type": "apk", "purl": None})
    await db.findings.insert_one(_finding("f-ssl", "openssl"))
    await db.findings.insert_one(_finding("f-zlib", "zlib"))

    types = {row["component"]: row["type"] for row in await _analytics(client, "hotspots", seeded)}

    assert types["openssl"] == "deb"
    assert types["zlib"] == "apk/deb"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_hotspot_type_matches_the_version_whatever_its_v_prefix(client, db, seeded):
    await db.dependencies.insert_one(
        {
            **_dependency("net-old", name="golang.org/x/net"),
            "group": None,
            "version": "v0.17.0",
            "type": "golang",
            "purl": "pkg:golang/golang.org/x/net@v0.17.0",
        }
    )
    await db.dependencies.insert_one(
        {
            **_dependency("net-new", name="golang.org/x/net"),
            "group": None,
            "version": "v0.23.0",
            "type": "library",
            "purl": None,
        }
    )
    await db.findings.insert_one({**_finding("f-net", "golang.org/x/net"), "version": "0.17.0"})

    types = {row["component"]: row["type"] for row in await _analytics(client, "hotspots", seeded)}

    assert types["golang.org/x/net"] == "golang"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_metadata_survives_rows_that_differ_only_in_stored_type(client, db, seeded):
    lodash = {"type": "library", "name": "lodash", "version": "4.17.21"}
    await _store_cyclonedx(
        db,
        lodash,
        {**lodash, "purl": "pkg:npm/lodash@4.17.21", "licenses": [{"license": {"id": "MIT"}}]},
    )

    metadata = await _analytics(client, "dependency-metadata", seeded, component="lodash")

    assert metadata is not None
    assert (metadata["purl"], metadata["type"], metadata["license"]) == ("pkg:npm/lodash@4.17.21", "npm", "MIT")


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_metadata_does_not_merge_two_ecosystems_that_share_a_path(client, db, seeded):
    debug = {"type": "library", "name": "debug", "version": "1.0.0"}
    await _store_cyclonedx(
        db,
        {**debug, "purl": "pkg:npm/debug@1.0.0"},
        {**debug, "purl": "pkg:pypi/debug@1.0.0"},
        debug,
    )

    assert await _analytics(client, "dependency-metadata", seeded, component="debug") is None


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_vulnerability_filter_tells_a_package_s_versions_apart(client, db, seeded):
    await db.dependencies.insert_one({**_dependency("lodash-old", name="lodash"), "version": "4.17.15", "type": "npm"})
    await db.dependencies.insert_one({**_dependency("lodash-new", name="lodash"), "version": "4.17.21", "type": "npm"})
    await db.findings.insert_one({**_finding("f-lodash", "lodash"), "version": "v4.17.15"})

    vulnerable = await _analytics(client, "search", seeded, q="lodash", has_vulnerabilities="true")
    clean = await _analytics(client, "search", seeded, q="lodash", has_vulnerabilities="false")

    assert [item["version"] for item in vulnerable["items"]] == ["4.17.15"]
    assert [item["version"] for item in clean["items"]] == ["4.17.21"]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_top_dependencies_name_the_group_of_each_same_named_package(client, db, seeded):
    await db.dependencies.insert_one(_maven("zxing", "com.google.zxing"))
    await db.dependencies.insert_one(_maven("jdt", "org.eclipse.jdt"))

    rows = await _analytics(client, "dependencies/top", seeded)

    assert sorted(row["group"] for row in rows if row["name"] == "core") == ["com.google.zxing", "org.eclipse.jdt"]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_top_dependencies_name_a_package_the_same_whatever_the_row_order(client, db, seeded):
    django = {"version": "4.2.0", "group": None, "type": "pypi", "purl": "pkg:pypi/django@4.2.0"}
    await db.dependencies.insert_one({**_dependency("dj-lower", name="django"), **django})
    await db.dependencies.insert_one({**_dependency("dj-upper", name="Django"), **django})

    rows = await _analytics(client, "dependencies/top", seeded)

    assert [row["name"] for row in rows if row["name"].lower() == "django"] == ["Django"]
