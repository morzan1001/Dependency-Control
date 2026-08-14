"""deps.dev fields must round-trip: what the analyzer fetches, to_mongo_dict persists and the UI reads.

Metadata dicts mirror `DepsDevAnalyzer._extract_metadata` / `_enrich_with_project`
output (prod: deps_dev.project_url was written on 0 of 12,876 docs, so the
Scorecard link never rendered).
"""

from app.schemas.enrichment import DependencyEnrichment
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


def test_links_homepage_wins_over_project_homepage():
    payload = _payload(_metadata())
    assert payload["homepage"] == "https://lodash.com/"


def test_project_homepage_fills_in_when_links_have_none():
    metadata = _metadata(links={"repository": "https://github.com/lodash/lodash"})
    payload = _payload(metadata)
    assert payload["homepage"] == "https://lodash.com/custom"


def test_dead_fields_are_gone_from_the_model():
    for field in ("download_url", "is_default_version", "scorecard_checks", "scorecard_critical_issues"):
        assert field not in DependencyEnrichment.model_fields
