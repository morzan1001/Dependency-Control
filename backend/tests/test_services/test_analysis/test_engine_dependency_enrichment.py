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
