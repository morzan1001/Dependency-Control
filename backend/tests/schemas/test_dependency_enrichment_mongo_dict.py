"""DependencyEnrichment.to_mongo_dict: which fields persist, under which keys, and in which order."""

from app.schemas.enrichment import DependencyEnrichment


def _enrichment(**fields) -> DependencyEnrichment:
    return DependencyEnrichment(name="lodash", version="4.17.21", **fields)


def test_an_enrichment_with_only_identity_fields_stores_nothing():
    assert _enrichment(purl="pkg:npm/lodash@4.17.21").to_mongo_dict() == {}


def test_every_populated_field_lands_under_its_stored_key():
    stored = _enrichment(
        licenses=[{"spdx_id": "MIT"}],
        primary_license="MIT",
        license_expression="MIT OR Apache-2.0",
        license_category="permissive",
        license_risks=["none"],
        license_obligations=["attribution"],
        homepage="https://lodash.com",
        repository_url="https://github.com/lodash/lodash",
        deps_dev={
            "project_url": "https://github.com/lodash/lodash",
            "links": {"funding": "https://opencollective.com/lodash"},
        },
        description="A modern JavaScript utility library.",
        sources=["sbom", "deps_dev"],
    ).to_mongo_dict()

    assert list(stored) == [
        "license",
        "license_expression",
        "license_category",
        "licenses_detailed",
        "license_risks",
        "license_obligations",
        "homepage",
        "repository_url",
        "deps_dev",
        "description",
        "enrichment_sources",
    ]
    assert stored["license"] == "MIT"
    assert stored["licenses_detailed"] == [{"spdx_id": "MIT"}]
    assert stored["enrichment_sources"] == ["sbom", "deps_dev"]
    assert stored["deps_dev"] == {
        "project_url": "https://github.com/lodash/lodash",
        "links": {"funding": "https://opencollective.com/lodash"},
    }


def test_empty_strings_and_an_empty_deps_dev_block_are_left_out():
    stored = _enrichment(
        primary_license="",
        homepage="",
        description="",
        deps_dev={},
    ).to_mongo_dict()

    assert stored == {}
