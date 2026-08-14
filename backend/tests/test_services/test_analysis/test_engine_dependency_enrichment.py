"""_enrich_dependencies: purl-keyed cross-scan upserts plus a slim per-scan dependency copy.

Prod shapes: multi-SBOM scans store qualifier-variant twins of the same artifact
(`...opencsv@5.12.0?type=jar` next to `...opencsv@5.12.0`), and the aggregator
emits one entry per canonical purl.
"""

import asyncio

from app.services.analysis.engine import _enrich_dependencies
from tests.mocks.fake_mongo import FakeDatabase


def _entry(name, version, purl, data):
    return {"name": name, "version": version, "purl": purl, "data": data}


def _run(db, entries):
    asyncio.run(_enrich_dependencies(entries, "scan-1", db))


def _insert_dep(db, **doc):
    asyncio.run(db.dependencies.insert_one({"scan_id": "scan-1", **doc}))


def _find_dep(db, **query):
    return asyncio.run(db.dependencies.find_one({"scan_id": "scan-1", **query}))


def test_upserts_enrichment_keyed_by_canonical_purl():
    db = FakeDatabase()
    _insert_dep(db, name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")

    _run(
        db,
        [_entry("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", {"license_category": "permissive", "license": "MIT"})],
    )

    doc = asyncio.run(db.dependency_enrichments.find_one({"purl": "pkg:npm/lodash@4.17.21"}))
    assert doc is not None
    assert doc["license"] == "MIT"
    assert doc["license_category"] == "permissive"
    assert doc["name"] == "lodash"
    assert doc["version"] == "4.17.21"


def test_no_enrichment_upsert_without_purl():
    db = FakeDatabase()
    _insert_dep(db, name="left-pad", version="1.0.0")

    _run(db, [_entry("left-pad", "1.0.0", None, {"license_category": "unknown"})])

    assert asyncio.run(db.dependency_enrichments.count_documents({})) == 0


def test_entry_without_purl_still_updates_dependency_doc():
    db = FakeDatabase()
    _insert_dep(db, name="left-pad", version="1.0.0")

    _run(db, [_entry("left-pad", "1.0.0", None, {"license_category": "permissive"})])

    assert _find_dep(db, name="left-pad", version="1.0.0")["license_category"] == "permissive"


def test_all_qualifier_variant_twins_receive_enrichment():
    # W13: image SBOM + application SBOM of the same build store two docs whose
    # purls differ only by qualifiers; both must be enriched.
    db = FakeDatabase()
    _insert_dep(db, name="opencsv", version="5.12.0", purl="pkg:maven/com.opencsv/opencsv@5.12.0?type=jar")
    _insert_dep(db, name="opencsv", version="5.12.0", purl="pkg:maven/com.opencsv/opencsv@5.12.0")

    _run(db, [_entry("opencsv", "5.12.0", "pkg:maven/com.opencsv/opencsv@5.12.0", {"license_category": "permissive"})])

    for purl in ("pkg:maven/com.opencsv/opencsv@5.12.0?type=jar", "pkg:maven/com.opencsv/opencsv@5.12.0"):
        assert _find_dep(db, purl=purl)["license_category"] == "permissive"
    assert asyncio.run(db.dependency_enrichments.count_documents({})) == 1


def test_purl_less_entry_does_not_stamp_a_purl_bearing_twin():
    """A purl-less enrichment describes an unidentified package, so its bare
    {scan_id, name, version} filter also matched an identified same-named package of
    another ecosystem. Latent today (0 of 200 sampled prod deps lack a purl)."""
    db = FakeDatabase()
    _insert_dep(db, name="crypto", version="1.0.0")
    _insert_dep(db, name="crypto", version="1.0.0", purl="pkg:golang/crypto@1.0.0")

    _run(db, [_entry("crypto", "1.0.0", None, {"license": "MIT", "license_category": "permissive"})])

    assert _find_dep(db, purl=None)["license_category"] == "permissive"
    assert "license_category" not in _find_dep(db, purl="pkg:golang/crypto@1.0.0")


def test_cross_ecosystem_twin_is_not_touched():
    # Same name@version from different ecosystems must not share enrichment.
    db = FakeDatabase()
    _insert_dep(db, name="foo", version="1.0.0", purl="pkg:npm/foo@1.0.0")
    _insert_dep(db, name="foo", version="1.0.0", purl="pkg:deb/debian/foo@1.0.0")

    _run(db, [_entry("foo", "1.0.0", "pkg:npm/foo@1.0.0", {"license_category": "permissive"})])

    assert _find_dep(db, purl="pkg:npm/foo@1.0.0")["license_category"] == "permissive"
    assert "license_category" not in _find_dep(db, purl="pkg:deb/debian/foo@1.0.0")


def test_sbom_declared_license_survives_but_twin_without_license_is_filled():
    db = FakeDatabase()
    _insert_dep(
        db, name="cdi-api", version="1.0", purl="pkg:maven/javax.enterprise/cdi-api@1.0?type=jar", license="EPL-2.0"
    )
    _insert_dep(db, name="cdi-api", version="1.0", purl="pkg:maven/javax.enterprise/cdi-api@1.0")

    _run(
        db,
        [
            _entry(
                "cdi-api",
                "1.0",
                "pkg:maven/javax.enterprise/cdi-api@1.0",
                {"license": "Apache-2.0", "license_category": "permissive"},
            )
        ],
    )

    with_license = _find_dep(db, purl="pkg:maven/javax.enterprise/cdi-api@1.0?type=jar")
    without_license = _find_dep(db, purl="pkg:maven/javax.enterprise/cdi-api@1.0")
    assert with_license["license"] == "EPL-2.0"
    assert with_license["license_category"] == "permissive"
    assert without_license["license"] == "Apache-2.0"
    assert without_license["license_category"] == "permissive"
    enrichment = asyncio.run(db.dependency_enrichments.find_one({"purl": "pkg:maven/javax.enterprise/cdi-api@1.0"}))
    assert enrichment["license"] == "Apache-2.0"


def test_persists_license_expression_on_dependency_and_enrichment_docs():
    db = FakeDatabase()
    expression = "BSD-3-Clause AND GPL-2.0-only"
    _insert_dep(db, name="libzstd", version="1.5.5", purl="pkg:rpm/redhat/libzstd@1.5.5", license=expression)

    _run(
        db,
        [
            _entry(
                "libzstd",
                "1.5.5",
                "pkg:rpm/redhat/libzstd@1.5.5",
                {"license": "GPL-2.0-only", "license_expression": expression},
            )
        ],
    )

    dep = _find_dep(db, name="libzstd", version="1.5.5")
    assert dep["license"] == expression
    assert dep["license_expression"] == expression
    enrichment = asyncio.run(db.dependency_enrichments.find_one({"purl": "pkg:rpm/redhat/libzstd@1.5.5"}))
    assert enrichment["license"] == "GPL-2.0-only"
    assert enrichment["license_expression"] == expression


def test_bulky_payload_stays_off_the_dependency_doc():
    # K15: deps_dev/description/links/licenses_detailed live once per purl in
    # dependency_enrichments, not on every per-scan dependency doc.
    db = FakeDatabase()
    _insert_dep(db, name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")
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

    _run(db, [_entry("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", payload)])

    dep = _find_dep(db, name="lodash", version="4.17.21")
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
        assert heavy_key not in dep

    enrichment = asyncio.run(db.dependency_enrichments.find_one({"purl": "pkg:npm/lodash@4.17.21"}))
    for key, value in payload.items():
        assert enrichment[key] == value


def test_empty_payload_entries_are_skipped():
    db = FakeDatabase()
    _insert_dep(db, name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")

    _run(db, [_entry("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", {})])

    assert asyncio.run(db.dependency_enrichments.count_documents({})) == 0
