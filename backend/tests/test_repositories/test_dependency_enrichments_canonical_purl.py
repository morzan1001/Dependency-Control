"""Enrichment lookups must resolve qualifier/subpath purl variants to the canonical doc.

Prod shape: enrichment docs are keyed by the canonical purl (no qualifiers), while
dependency docs carry tool-specific qualifier variants like `?type=jar` or
`?goarch=amd64&goos=linux&type=module`.
"""

import asyncio

from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.services.analyzers.purl_utils import canonical_purl
from tests.mocks.fake_mongo import FakeDatabase

CANONICAL = "pkg:maven/com.opencsv/opencsv@5.12.0"
QUALIFIED = "pkg:maven/com.opencsv/opencsv@5.12.0?type=jar"
GO_CANONICAL = "pkg:golang/github.com/blang/semver/v4@v4.0.0"
GO_QUALIFIED = "pkg:golang/github.com/blang/semver/v4@v4.0.0?goarch=amd64&goos=linux&type=module"


class TestCanonicalPurl:
    def test_strips_qualifiers(self):
        assert canonical_purl(QUALIFIED) == CANONICAL

    def test_strips_multi_qualifiers(self):
        assert canonical_purl(GO_QUALIFIED) == GO_CANONICAL

    def test_strips_subpath(self):
        assert canonical_purl("pkg:npm/lodash@4.17.21#lib") == "pkg:npm/lodash@4.17.21"

    def test_strips_qualifiers_and_subpath(self):
        assert canonical_purl("pkg:deb/debian/apt@3.0.3?arch=amd64&distro=debian-13#usr") == (
            "pkg:deb/debian/apt@3.0.3"
        )

    def test_canonical_purl_is_unchanged(self):
        assert canonical_purl(CANONICAL) == CANONICAL

    def test_empty_string_passes_through(self):
        assert canonical_purl("") == ""


def _db_with_enrichment(purl: str) -> FakeDatabase:
    db = FakeDatabase()
    asyncio.run(
        db.dependency_enrichments.insert_one(
            {"purl": purl, "name": "opencsv", "version": "5.12.0", "license": "Apache-2.0"}
        )
    )
    return db


class TestGetByPurl:
    def test_qualified_lookup_hits_canonical_doc(self):
        db = _db_with_enrichment(CANONICAL)
        doc = asyncio.run(DependencyEnrichmentRepository(db).get_by_purl(QUALIFIED))
        assert doc is not None
        assert doc["license"] == "Apache-2.0"

    def test_canonical_lookup_still_hits(self):
        db = _db_with_enrichment(CANONICAL)
        doc = asyncio.run(DependencyEnrichmentRepository(db).get_by_purl(CANONICAL))
        assert doc is not None


class TestGetManyByPurls:
    def test_result_is_keyed_by_requested_purl(self):
        db = _db_with_enrichment(CANONICAL)
        result = asyncio.run(DependencyEnrichmentRepository(db).get_many_by_purls([QUALIFIED]))
        assert QUALIFIED in result
        assert result[QUALIFIED]["license"] == "Apache-2.0"

    def test_mixed_variants_of_same_artifact_resolve_to_one_doc(self):
        db = _db_with_enrichment(CANONICAL)
        result = asyncio.run(DependencyEnrichmentRepository(db).get_many_by_purls([QUALIFIED, CANONICAL]))
        assert result[QUALIFIED] == result[CANONICAL]

    def test_unknown_purl_is_absent(self):
        db = _db_with_enrichment(CANONICAL)
        result = asyncio.run(DependencyEnrichmentRepository(db).get_many_by_purls([GO_QUALIFIED]))
        assert result == {}

    def test_empty_input(self):
        db = FakeDatabase()
        result = asyncio.run(DependencyEnrichmentRepository(db).get_many_by_purls([]))
        assert result == {}
