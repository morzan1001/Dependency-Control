"""_get_enrichment_info reads the shape DependencyEnrichment.to_mongo_dict() persists."""

import asyncio
from unittest.mock import AsyncMock

from app.api.v1.endpoints.analytics.dependencies import EnrichmentInfo, _get_enrichment_info
from app.schemas.enrichment import DependencyEnrichment


def test_returns_defaults_when_purl_missing():
    repo = AsyncMock()

    result = asyncio.run(_get_enrichment_info(repo, None))

    assert result == EnrichmentInfo()
    repo.get_by_purl.assert_not_awaited()


def test_returns_defaults_when_no_enrichment_doc():
    repo = AsyncMock()
    repo.get_by_purl.return_value = None

    result = asyncio.run(_get_enrichment_info(repo, "pkg:npm/lodash@4.17.21"))

    assert result == EnrichmentInfo()


def test_extracts_top_level_license_fields_and_deps_dev_subdoc():
    repo = AsyncMock()
    enrichment = DependencyEnrichment(
        name="lodash",
        version="4.17.21",
        license_category="permissive",
        license_risks=["some risk"],
        license_obligations=["attribution"],
        deps_dev={"stars": 100, "forks": 10},
        sources=["deps_dev", "license_compliance"],
        description="Lodash modular utilities.",
        homepage="https://lodash.com/",
        repository_url="https://github.com/lodash/lodash",
    )
    repo.get_by_purl.return_value = {"purl": "pkg:npm/lodash@4.17.21", **enrichment.to_mongo_dict()}

    result = asyncio.run(_get_enrichment_info(repo, "pkg:npm/lodash@4.17.21"))

    assert result == EnrichmentInfo(
        deps_dev={"stars": 100, "forks": 10},
        enrichment_sources=["deps_dev", "license_compliance"],
        license_category="permissive",
        license_risks=["some risk"],
        license_obligations=["attribution"],
        description="Lodash modular utilities.",
        homepage="https://lodash.com/",
        repository_url="https://github.com/lodash/lodash",
    )


def test_reports_the_sources_the_enrichment_doc_records():
    repo = AsyncMock()
    # deps.dev answered with a license list only, so no deps_dev block was stored.
    enrichment = DependencyEnrichment(name="tiny", version="1.0.0", sources=["deps_dev"])
    repo.get_by_purl.return_value = {"purl": "pkg:npm/tiny@1.0.0", **enrichment.to_mongo_dict()}

    result = asyncio.run(_get_enrichment_info(repo, "pkg:npm/tiny@1.0.0"))

    assert result == EnrichmentInfo(enrichment_sources=["deps_dev"])
