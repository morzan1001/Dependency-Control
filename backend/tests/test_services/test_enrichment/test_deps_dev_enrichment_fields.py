"""deps.dev fields must round-trip: what the analyzer fetches, to_mongo_dict persists and the UI reads.

Metadata dicts mirror `DepsDevAnalyzer._extract_metadata` / `_enrich_with_project`
output (prod: deps_dev.project_url was written on 0 of 12,876 docs, so the
Scorecard link never rendered).
"""

from app.services.aggregation import ResultAggregator
from tests.helpers.enrichment import enrichment_payload


def _metadata(**overrides):
    metadata = {
        "name": "lodash",
        "version": "4.17.21",
        "system": "npm",
        "purl": "pkg:npm/lodash@4.17.21",
        "published_at": "2021-02-20T15:42:16Z",
        "is_deprecated": False,
        "licenses": ["MIT"],
        "links": {"homepage": "https://lodash.com/", "repository": "https://github.com/lodash/lodash"},
        "has_attestations": False,
        "has_slsa_provenance": False,
        "project": {
            "id": "github.com/lodash/lodash",
            "url": "https://github.com/lodash/lodash",
            "stars": 58000,
            "forks": 7000,
            "open_issues": 100,
            "description": "A modern JavaScript utility library.",
            "homepage": "https://lodash.com/custom",
            "license": "MIT",
        },
        "dependents": {"total": 200000, "direct": 150000, "indirect": 50000},
        "scorecard": {"overall_score": 5.6, "date": "2026-08-01", "checks_count": 12},
    }
    metadata.update(overrides)
    return metadata


def _payload(metadata):
    agg = ResultAggregator()
    agg.enrich_from_deps_dev("lodash", "4.17.21", metadata)
    return enrichment_payload(agg, "lodash", "4.17.21")


def test_project_url_is_persisted_for_the_scorecard_link():
    payload = _payload(_metadata())
    assert payload["deps_dev"]["project_url"] == "https://github.com/lodash/lodash"


def test_indirect_dependents_are_persisted():
    payload = _payload(_metadata())
    assert payload["deps_dev"]["dependents"] == {"total": 200000, "direct": 150000, "indirect": 50000}


def test_scorecard_is_persisted_under_the_key_the_modal_reads():
    payload = _payload(_metadata())
    assert payload["deps_dev"]["scorecard"] == {"overall_score": 5.6, "date": "2026-08-01", "checks_count": 12}


def test_links_homepage_wins_over_project_homepage():
    payload = _payload(_metadata())
    assert payload["homepage"] == "https://lodash.com/"


def test_project_homepage_fills_in_when_links_have_none():
    metadata = _metadata(links={"repository": "https://github.com/lodash/lodash"})
    payload = _payload(metadata)
    assert payload["homepage"] == "https://lodash.com/custom"


def test_the_persisted_deps_dev_block_carries_exactly_the_analyzer_fields():
    metadata = _metadata(
        is_deprecated=True,
        has_attestations=True,
        known_advisories=["GHSA-35jh-r3h4-6jhm"],
        links={
            "homepage": "https://lodash.com/",
            "repository": "https://github.com/lodash/lodash",
            "documentation": "https://lodash.com/docs",
            "issues": "https://github.com/lodash/lodash/issues",
            "funding": "https://opencollective.com/lodash",
        },
    )
    metadata["scorecard"] = {**metadata["scorecard"], "checks": [{"name": "Maintained", "score": 0}]}

    assert _payload(metadata)["deps_dev"] == {
        "project_url": "https://github.com/lodash/lodash",
        "stars": 58000,
        "forks": 7000,
        "open_issues": 100,
        "dependents": {"total": 200000, "direct": 150000, "indirect": 50000},
        "scorecard": {"overall_score": 5.6, "date": "2026-08-01", "checks_count": 12},
        "links": {
            "documentation": "https://lodash.com/docs",
            "issues": "https://github.com/lodash/lodash/issues",
            "funding": "https://opencollective.com/lodash",
        },
        "published_at": "2021-02-20T15:42:16Z",
        "is_deprecated": True,
        "known_advisories": ["GHSA-35jh-r3h4-6jhm"],
        "has_attestations": True,
    }


def test_zero_counts_persist_and_false_flags_stay_out():
    metadata = _metadata(
        links={}, project={"id": "github.com/x/y", "url": None, "stars": 0, "forks": 0, "open_issues": 0}
    )
    metadata["dependents"] = {"total": 0, "direct": 0, "indirect": 0}
    metadata["scorecard"] = {"overall_score": 0, "date": None, "checks_count": 0}

    assert _payload(metadata)["deps_dev"] == {
        "stars": 0,
        "forks": 0,
        "open_issues": 0,
        "dependents": {"total": 0, "direct": 0, "indirect": 0},
        "scorecard": {"overall_score": 0, "date": None, "checks_count": 0},
        "published_at": "2021-02-20T15:42:16Z",
    }


def test_links_from_qualifier_variants_accumulate():
    agg = ResultAggregator()
    agg.enrich_from_deps_dev("lodash", "4.17.21", _metadata(links={"documentation": "https://lodash.com/docs"}))
    agg.enrich_from_deps_dev(
        "lodash",
        "4.17.21",
        _metadata(purl="pkg:npm/lodash@4.17.21?type=tgz", links={"funding": "https://opencollective.com/lodash"}),
    )

    assert enrichment_payload(agg, "lodash", "4.17.21")["deps_dev"]["links"] == {
        "documentation": "https://lodash.com/docs",
        "funding": "https://opencollective.com/lodash",
    }


def test_version_license_stays_primary_over_a_relicensed_repository():
    metadata = _metadata(
        name="github.com/hashicorp/vault/api",
        version="1.9.0",
        purl="pkg:golang/github.com/hashicorp/vault/api@v1.9.0",
        licenses=["MPL-2.0"],
        project={
            "id": "github.com/hashicorp/vault",
            "url": "https://github.com/hashicorp/vault",
            "license": "BUSL-1.1",
        },
    )
    agg = ResultAggregator()
    agg.enrich_from_deps_dev("github.com/hashicorp/vault/api", "1.9.0", metadata)
    payload = enrichment_payload(agg, "github.com/hashicorp/vault/api", "1.9.0")

    assert payload["license"] == "MPL-2.0"
    assert payload["licenses_detailed"] == [
        {"spdx_id": "MPL-2.0", "source": "deps_dev"},
        {"spdx_id": "BUSL-1.1", "source": "deps_dev_project"},
    ]


def test_a_package_in_two_sboms_records_each_license_once():
    result = {"scorecard_issues": [], "package_metadata": {"npm:lodash@4.17.21": _metadata()}}
    agg = ResultAggregator()
    agg.aggregate("deps_dev", result, source="SBOM #1")
    agg.aggregate("deps_dev", result, source="SBOM #2")

    assert enrichment_payload(agg, "lodash", "4.17.21")["licenses_detailed"] == [
        {"spdx_id": "MIT", "source": "deps_dev"},
        {"spdx_id": "MIT", "source": "deps_dev_project"},
    ]
