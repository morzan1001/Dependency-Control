"""Multi-SBOM scans store qualifier-variant twins of one artifact; the aggregator emits one entry per canonical purl."""

import asyncio

import pytest

from app.schemas.sbom import ParsedDependency, ParsedSBOM, SBOMFormat
from app.services.analysis.engine import _store_dependencies
from tests.mocks.fake_mongo import FakeDatabase


class _Inventory:
    def __init__(self, written: bool) -> None:
        self.db = FakeDatabase()
        self._written = written
        self._parsed: list[ParsedDependency] = []

    def add(self, **dep):
        if self._written:
            self._parsed.append(ParsedDependency(**dep))
        else:
            asyncio.run(self.db.dependencies.insert_one({"scan_id": "scan-1", **dep}))

    def enrich(self, entries):
        payload = [ParsedSBOM(format=SBOMFormat.CYCLONEDX, dependencies=self._parsed)] if self._written else [None]
        asyncio.run(_store_dependencies(payload, "p", "scan-1", self.db, entries))

    def find(self, **query):
        return asyncio.run(self.db.dependencies.find_one({"scan_id": "scan-1", **query}))


@pytest.fixture(params=["written", "kept"])
def inventory(request) -> _Inventory:
    return _Inventory(request.param == "written")


def _entry(name, version, purl, data):
    return {"name": name, "version": version, "purl": purl, "data": data}


def test_upserts_enrichment_keyed_by_canonical_purl(inventory):
    inventory.add(name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")

    inventory.enrich(
        [_entry("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", {"license_category": "permissive", "license": "MIT"})],
    )

    doc = asyncio.run(inventory.db.dependency_enrichments.find_one({"purl": "pkg:npm/lodash@4.17.21"}))
    assert doc is not None
    assert doc["license"] == "MIT"
    assert doc["license_category"] == "permissive"
    assert doc["name"] == "lodash"
    assert doc["version"] == "4.17.21"


def test_no_enrichment_upsert_without_purl(inventory):
    inventory.add(name="left-pad", version="1.0.0")

    inventory.enrich([_entry("left-pad", "1.0.0", None, {"license_category": "unknown"})])

    assert asyncio.run(inventory.db.dependency_enrichments.count_documents({})) == 0


def test_entry_without_purl_still_updates_dependency_doc(inventory):
    inventory.add(name="left-pad", version="1.0.0")

    inventory.enrich([_entry("left-pad", "1.0.0", None, {"license_category": "permissive"})])

    assert inventory.find(name="left-pad", version="1.0.0")["license_category"] == "permissive"


def test_all_qualifier_variant_twins_receive_enrichment(inventory):
    # Image and application SBOMs of one build store two docs whose purls differ only by qualifiers.
    inventory.add(name="opencsv", version="5.12.0", purl="pkg:maven/com.opencsv/opencsv@5.12.0?type=jar")
    inventory.add(name="opencsv", version="5.12.0", purl="pkg:maven/com.opencsv/opencsv@5.12.0")

    inventory.enrich(
        [_entry("opencsv", "5.12.0", "pkg:maven/com.opencsv/opencsv@5.12.0", {"license_category": "permissive"})]
    )

    for purl in ("pkg:maven/com.opencsv/opencsv@5.12.0?type=jar", "pkg:maven/com.opencsv/opencsv@5.12.0"):
        assert inventory.find(purl=purl)["license_category"] == "permissive"
    assert asyncio.run(inventory.db.dependency_enrichments.count_documents({})) == 1


def test_purl_less_entry_does_not_stamp_a_purl_bearing_twin(inventory):
    """A purl-less entry's bare {scan_id, name, version} filter would also match a same-named package elsewhere."""
    inventory.add(name="crypto", version="1.0.0")
    inventory.add(name="crypto", version="1.0.0", purl="pkg:golang/crypto@1.0.0")

    inventory.enrich([_entry("crypto", "1.0.0", None, {"license": "MIT", "license_category": "permissive"})])

    assert inventory.find(purl=None)["license_category"] == "permissive"
    assert inventory.find(purl="pkg:golang/crypto@1.0.0").get("license_category") is None


def test_cross_ecosystem_twin_is_not_touched(inventory):
    inventory.add(name="foo", version="1.0.0", purl="pkg:npm/foo@1.0.0")
    inventory.add(name="foo", version="1.0.0", purl="pkg:deb/debian/foo@1.0.0")

    inventory.enrich([_entry("foo", "1.0.0", "pkg:npm/foo@1.0.0", {"license_category": "permissive"})])

    assert inventory.find(purl="pkg:npm/foo@1.0.0")["license_category"] == "permissive"
    assert inventory.find(purl="pkg:deb/debian/foo@1.0.0").get("license_category") is None


def test_a_purl_that_merely_starts_with_the_enriched_one_is_not_touched(inventory):
    inventory.add(name="foo", version="1.0.0", purl="pkg:npm/foo@1.0.0#dist/foo.js")
    inventory.add(name="foo", version="1.0.01", purl="pkg:npm/foo@1.0.01")
    inventory.add(name="foo", version="1.0.0-beta", purl="pkg:npm/foo@1.0.0-beta")

    inventory.enrich([_entry("foo", "1.0.0", "pkg:npm/foo@1.0.0", {"license_category": "permissive"})])

    assert inventory.find(purl="pkg:npm/foo@1.0.0#dist/foo.js")["license_category"] == "permissive"
    assert inventory.find(purl="pkg:npm/foo@1.0.01").get("license_category") is None
    assert inventory.find(purl="pkg:npm/foo@1.0.0-beta").get("license_category") is None


def test_sbom_declared_license_survives_but_twin_without_license_is_filled(inventory):
    inventory.add(
        name="cdi-api", version="1.0", purl="pkg:maven/javax.enterprise/cdi-api@1.0?type=jar", license="EPL-2.0"
    )
    inventory.add(name="cdi-api", version="1.0", purl="pkg:maven/javax.enterprise/cdi-api@1.0")

    inventory.enrich(
        [
            _entry(
                "cdi-api",
                "1.0",
                "pkg:maven/javax.enterprise/cdi-api@1.0",
                {"license": "Apache-2.0", "license_category": "permissive"},
            )
        ],
    )

    with_license = inventory.find(purl="pkg:maven/javax.enterprise/cdi-api@1.0?type=jar")
    without_license = inventory.find(purl="pkg:maven/javax.enterprise/cdi-api@1.0")
    assert with_license["license"] == "EPL-2.0"
    assert with_license["license_category"] == "permissive"
    assert without_license["license"] == "Apache-2.0"
    assert without_license["license_category"] == "permissive"
    enrichment = asyncio.run(
        inventory.db.dependency_enrichments.find_one({"purl": "pkg:maven/javax.enterprise/cdi-api@1.0"})
    )
    assert enrichment["license"] == "Apache-2.0"


def test_persists_license_expression_on_dependency_and_enrichment_docs(inventory):
    expression = "BSD-3-Clause AND GPL-2.0-only"
    inventory.add(name="libzstd", version="1.5.5", purl="pkg:rpm/redhat/libzstd@1.5.5", license=expression)

    inventory.enrich(
        [
            _entry(
                "libzstd",
                "1.5.5",
                "pkg:rpm/redhat/libzstd@1.5.5",
                {"license": "GPL-2.0-only", "license_expression": expression},
            )
        ],
    )

    dep = inventory.find(name="libzstd", version="1.5.5")
    assert dep["license"] == expression
    assert dep["license_expression"] == expression
    enrichment = asyncio.run(inventory.db.dependency_enrichments.find_one({"purl": "pkg:rpm/redhat/libzstd@1.5.5"}))
    assert enrichment["license"] == "GPL-2.0-only"
    assert enrichment["license_expression"] == expression


def test_bulky_payload_stays_off_the_dependency_doc(inventory):
    # deps_dev, description, links and licenses_detailed live once per purl, not on every per-scan doc.
    inventory.add(name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")
    payload = {
        "license": "MIT",
        "license_category": "permissive",
        "license_risks": ["some risk"],
        "licenses_detailed": [{"spdx_id": "MIT", "source": "license_compliance"}],
        "license_obligations": ["attribution"],
        "description": "Lodash modular utilities.",
        "homepage": "https://lodash.com/",
        "repository_url": "https://github.com/lodash/lodash",
        "deps_dev": {"stars": 58000, "scorecard": {"overall_score": 5.6}},
        "enrichment_sources": ["deps_dev", "license_compliance"],
    }

    inventory.enrich([_entry("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", payload)])

    dep = inventory.find(name="lodash", version="4.17.21")
    assert dep["license"] == "MIT"
    assert dep["license_category"] == "permissive"
    assert dep["license_risks"] == ["some risk"]
    for heavy_key in (
        "deps_dev",
        "description",
        "homepage",
        "repository_url",
        "licenses_detailed",
        "enrichment_sources",
        "license_obligations",
    ):
        assert dep.get(heavy_key) is None

    enrichment = asyncio.run(inventory.db.dependency_enrichments.find_one({"purl": "pkg:npm/lodash@4.17.21"}))
    for key, value in payload.items():
        assert enrichment[key] == value


def test_empty_payload_entries_are_skipped(inventory):
    inventory.add(name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")

    inventory.enrich([_entry("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", {})])

    assert asyncio.run(inventory.db.dependency_enrichments.count_documents({})) == 0


def test_the_recorded_sources_accumulate_across_scans_like_the_data_they_describe(inventory):
    purl = "pkg:npm/lodash@4.17.21"

    inventory.enrich(
        [_entry("lodash", "4.17.21", purl, {"license": "MIT", "enrichment_sources": ["license_compliance"]})]
    )
    inventory.enrich(
        [_entry("lodash", "4.17.21", purl, {"deps_dev": {"stars": 1}, "enrichment_sources": ["deps_dev"]})]
    )

    doc = asyncio.run(inventory.db.dependency_enrichments.find_one({"purl": purl}))
    assert sorted(doc["enrichment_sources"]) == ["deps_dev", "license_compliance"]


def test_every_spelling_of_one_purl_receives_the_enrichment(inventory):
    """Two SBOMs of one scan name the same purl differently."""
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
    inventory.add(name="log4j-core", version="2.17.1", purl=purl)
    inventory.add(name="org.apache.logging.log4j:log4j-core", version="2.17.1", purl=purl)

    inventory.enrich([_entry("log4j-core", "2.17.1", purl, {"license_category": "permissive"})])

    for name in ("log4j-core", "org.apache.logging.log4j:log4j-core"):
        assert inventory.find(name=name)["license_category"] == "permissive"
