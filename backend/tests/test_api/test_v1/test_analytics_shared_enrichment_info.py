"""_get_enrichment_info reads the shape DependencyEnrichment.to_mongo_dict() actually persists:
top-level license_category/license_risks/license_obligations plus a deps_dev subdoc."""

import asyncio
from unittest.mock import AsyncMock

from app.api.v1.endpoints.analytics._shared import _get_enrichment_info


def test_returns_defaults_when_purl_missing():
    repo = AsyncMock()

    result = asyncio.run(_get_enrichment_info(repo, None))

    assert result == {
        "deps_dev_data": None,
        "enrichment_sources": [],
        "license_category": None,
        "license_risks": [],
        "license_obligations": [],
    }
    repo.get_by_purl.assert_not_awaited()


def test_returns_defaults_when_no_enrichment_doc():
    repo = AsyncMock()
    repo.get_by_purl.return_value = None

    result = asyncio.run(_get_enrichment_info(repo, "pkg:npm/lodash@4.17.21"))

    assert result["license_category"] is None
    assert result["enrichment_sources"] == []


def test_extracts_top_level_license_fields_and_deps_dev_subdoc():
    repo = AsyncMock()
    repo.get_by_purl.return_value = {
        "purl": "pkg:npm/lodash@4.17.21",
        "license_category": "permissive",
        "license_risks": ["some risk"],
        "license_obligations": ["attribution"],
        "deps_dev": {"stars": 100, "forks": 10},
    }

    result = asyncio.run(_get_enrichment_info(repo, "pkg:npm/lodash@4.17.21"))

    assert result["license_category"] == "permissive"
    assert result["license_risks"] == ["some risk"]
    assert result["license_obligations"] == ["attribution"]
    assert result["deps_dev_data"] == {"stars": 100, "forks": 10}
    assert sorted(result["enrichment_sources"]) == ["deps_dev", "license_compliance"]
