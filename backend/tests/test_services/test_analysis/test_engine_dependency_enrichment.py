"""_enrich_dependencies persists aggregator enrichment payloads into dependency_enrichments, keyed by purl."""

import asyncio

from app.services.analysis.engine import _enrich_dependencies
from tests.mocks.fake_mongo import FakeDatabase


def test_upserts_dependency_enrichment_by_purl_when_dependency_has_purl():
    db = FakeDatabase()

    async def _run():
        await db.dependencies.insert_one(
            {"scan_id": "scan-1", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
        )
        await _enrich_dependencies(
            {"lodash@4.17.21": {"license_category": "permissive", "license": "MIT"}},
            "scan-1",
            db,
        )
        return await db.dependency_enrichments.find_one({"purl": "pkg:npm/lodash@4.17.21"})

    enrichment_doc = asyncio.run(_run())

    assert enrichment_doc is not None
    assert enrichment_doc["purl"] == "pkg:npm/lodash@4.17.21"
    assert enrichment_doc["license_category"] == "permissive"
    assert enrichment_doc["license"] == "MIT"
    assert enrichment_doc["name"] == "lodash"
    assert enrichment_doc["version"] == "4.17.21"


def test_skips_dependency_enrichment_upsert_when_dependency_has_no_purl():
    db = FakeDatabase()

    async def _run():
        await db.dependencies.insert_one({"scan_id": "scan-1", "name": "left-pad", "version": "1.0.0"})
        await _enrich_dependencies(
            {"left-pad@1.0.0": {"license_category": "unknown"}},
            "scan-1",
            db,
        )
        return await db.dependency_enrichments.count_documents({})

    count = asyncio.run(_run())

    assert count == 0


def test_still_applies_per_scan_dependency_set():
    db = FakeDatabase()

    async def _run():
        await db.dependencies.insert_one({"scan_id": "scan-1", "name": "lodash", "version": "4.17.21"})
        await _enrich_dependencies({"lodash@4.17.21": {"license_category": "permissive"}}, "scan-1", db)
        return await db.dependencies.find_one({"scan_id": "scan-1", "name": "lodash", "version": "4.17.21"})

    dep_doc = asyncio.run(_run())

    assert dep_doc["license_category"] == "permissive"


def test_does_not_overwrite_sbom_declared_license_on_dependency_doc():
    db = FakeDatabase()

    async def _run():
        await db.dependencies.insert_one(
            {
                "scan_id": "scan-1",
                "name": "cdi-api",
                "version": "1.0",
                "purl": "pkg:maven/javax.enterprise/cdi-api@1.0",
                "license": "EPL-2.0",
            }
        )
        await _enrich_dependencies(
            {"cdi-api@1.0": {"license": "MIT", "license_category": "permissive"}},
            "scan-1",
            db,
        )
        dep = await db.dependencies.find_one({"scan_id": "scan-1", "name": "cdi-api", "version": "1.0"})
        enr = await db.dependency_enrichments.find_one({"purl": "pkg:maven/javax.enterprise/cdi-api@1.0"})
        return dep, enr

    dep_doc, enrichment_doc = asyncio.run(_run())

    assert dep_doc["license"] == "EPL-2.0"
    assert dep_doc["license_category"] == "permissive"
    assert enrichment_doc["license"] == "MIT"


def test_sets_license_when_dependency_has_none():
    db = FakeDatabase()

    async def _run():
        await db.dependencies.insert_one({"scan_id": "scan-1", "name": "left-pad", "version": "1.0.0"})
        await _enrich_dependencies({"left-pad@1.0.0": {"license": "MIT"}}, "scan-1", db)
        return await db.dependencies.find_one({"scan_id": "scan-1", "name": "left-pad", "version": "1.0.0"})

    dep_doc = asyncio.run(_run())

    assert dep_doc["license"] == "MIT"


def test_license_only_payload_still_upserts_enrichment_when_dependency_keeps_its_license():
    db = FakeDatabase()

    async def _run():
        await db.dependencies.insert_one(
            {
                "scan_id": "scan-1",
                "name": "tzdata",
                "version": "2026c",
                "purl": "pkg:rpm/redhat/tzdata@2026c",
                "license": "LicenseRef-Fedora-Public-Domain AND (GPL-2.0-only WITH ClassPath-exception-2.0)",
            }
        )
        await _enrich_dependencies({"tzdata@2026c": {"license": "GPL-2.0-only"}}, "scan-1", db)
        dep = await db.dependencies.find_one({"scan_id": "scan-1", "name": "tzdata", "version": "2026c"})
        enr = await db.dependency_enrichments.find_one({"purl": "pkg:rpm/redhat/tzdata@2026c"})
        return dep, enr

    dep_doc, enrichment_doc = asyncio.run(_run())

    assert dep_doc["license"] == "LicenseRef-Fedora-Public-Domain AND (GPL-2.0-only WITH ClassPath-exception-2.0)"
    assert enrichment_doc["license"] == "GPL-2.0-only"


def test_persists_license_expression_on_dependency_and_enrichment_docs():
    db = FakeDatabase()
    expression = "BSD-3-Clause AND GPL-2.0-only"

    async def _run():
        await db.dependencies.insert_one(
            {
                "scan_id": "scan-1",
                "name": "libzstd",
                "version": "1.5.5",
                "purl": "pkg:rpm/redhat/libzstd@1.5.5",
                "license": expression,
            }
        )
        await _enrich_dependencies(
            {"libzstd@1.5.5": {"license": "GPL-2.0-only", "license_expression": expression}},
            "scan-1",
            db,
        )
        dep = await db.dependencies.find_one({"scan_id": "scan-1", "name": "libzstd", "version": "1.5.5"})
        enr = await db.dependency_enrichments.find_one({"purl": "pkg:rpm/redhat/libzstd@1.5.5"})
        return dep, enr

    dep_doc, enrichment_doc = asyncio.run(_run())

    assert dep_doc["license"] == expression
    assert dep_doc["license_expression"] == expression
    assert enrichment_doc["license_expression"] == expression
