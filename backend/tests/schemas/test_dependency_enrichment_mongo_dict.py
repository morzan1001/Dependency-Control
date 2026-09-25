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
        documentation_url="https://lodash.com/docs",
        issues_url="https://github.com/lodash/lodash/issues",
        changelog_url="https://github.com/lodash/lodash/releases",
        additional_links={"funding": "https://opencollective.com/lodash"},
        project_url="https://github.com/lodash/lodash",
        stars=58000,
        forks=7000,
        open_issues=100,
        dependents_total=200000,
        dependents_direct=150000,
        dependents_indirect=50000,
        scorecard_score=5.6,
        scorecard_date="2026-08-01",
        scorecard_checks_count=12,
        published_at="2021-02-20T15:42:16Z",
        is_deprecated=True,
        known_advisories=["GHSA-1"],
        has_attestations=True,
        has_slsa_provenance=True,
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
    assert list(stored["deps_dev"].items()) == [
        ("project_url", "https://github.com/lodash/lodash"),
        ("stars", 58000),
        ("forks", 7000),
        ("open_issues", 100),
        ("dependents", {"total": 200000, "direct": 150000, "indirect": 50000}),
        ("scorecard", {"overall_score": 5.6, "date": "2026-08-01", "checks_count": 12}),
        (
            "links",
            {
                "documentation": "https://lodash.com/docs",
                "issues": "https://github.com/lodash/lodash/issues",
                "changelog": "https://github.com/lodash/lodash/releases",
                "funding": "https://opencollective.com/lodash",
            },
        ),
        ("published_at", "2021-02-20T15:42:16Z"),
        ("is_deprecated", True),
        ("known_advisories", ["GHSA-1"]),
        ("has_attestations", True),
        ("has_slsa_provenance", True),
    ]


def test_zero_counts_persist_while_unset_subfields_stay_none():
    stored = _enrichment(stars=0, forks=0, open_issues=0, dependents_total=0, scorecard_score=0.0).to_mongo_dict()

    assert stored == {
        "deps_dev": {
            "stars": 0,
            "forks": 0,
            "open_issues": 0,
            "dependents": {"total": 0, "direct": None, "indirect": None},
            "scorecard": {"overall_score": 0.0, "date": None, "checks_count": None},
        }
    }


def test_additional_links_alone_create_the_links_block():
    stored = _enrichment(additional_links={"funding": "https://opencollective.com/lodash"}).to_mongo_dict()

    assert stored == {"deps_dev": {"links": {"funding": "https://opencollective.com/lodash"}}}


def test_an_additional_link_overrides_the_named_link_of_the_same_key():
    stored = _enrichment(
        documentation_url="https://lodash.com/docs", additional_links={"documentation": "https://mirror/docs"}
    ).to_mongo_dict()

    assert stored["deps_dev"]["links"] == {"documentation": "https://mirror/docs"}


def test_each_named_link_alone_creates_the_links_block():
    assert _enrichment(issues_url="https://i").to_mongo_dict() == {"deps_dev": {"links": {"issues": "https://i"}}}
    assert _enrichment(changelog_url="https://c").to_mongo_dict() == {"deps_dev": {"links": {"changelog": "https://c"}}}


def test_false_flags_and_empty_strings_are_left_out():
    stored = _enrichment(
        primary_license="",
        homepage="",
        description="",
        is_deprecated=False,
        has_attestations=False,
        has_slsa_provenance=False,
        known_advisories=[],
        additional_links={},
    ).to_mongo_dict()

    assert stored == {}


def test_each_flag_persists_on_its_own():
    assert _enrichment(is_deprecated=True).to_mongo_dict() == {"deps_dev": {"is_deprecated": True}}
    assert _enrichment(has_attestations=True).to_mongo_dict() == {"deps_dev": {"has_attestations": True}}
    assert _enrichment(has_slsa_provenance=True).to_mongo_dict() == {"deps_dev": {"has_slsa_provenance": True}}
