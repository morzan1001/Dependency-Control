"""Stats, dependency enrichments and recommendations come out of the same fold the scan pipeline uses."""

import pytest

from app.models.waiver import Waiver
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
from tests.mocks.fake_mongo import FakeDatabase
from tests.helpers.analyzers import serve_analyzer

_OSV = "osv"
_LICENSE_COMPLIANCE = "license_compliance"

_COMPONENT = "requests"
_VERSION = "2.31.0"
_FIXED_VERSION = "2.32.0"
_LICENSE = "MIT"
_LICENSE_CATEGORY = "permissive"

_OS_COMPONENT = "openssl"
_OS_VERSION = "3.1.0"
_IMAGE_NAME = "alpine"
_IMAGE_TAG = "3.18"
_SOURCE_TARGET = f"{_IMAGE_NAME}:{_IMAGE_TAG}"

_CVE = "CVE-2024-0001"
_SUMMARY = "demo"
_SEVERITY_CRITICAL = "CRITICAL"
_REASON = "accepted"
_CREATED_BY = "admin"

_DIRECT_DEPENDENCY_UPDATE = "direct_dependency_update"
_BASE_IMAGE_UPDATE = "base_image_update"
_RECOMMENDATION_KEYS = {"type", "priority", "title", "action"}
_ENRICHMENT_KEYS = {"name", "version", "purl", "data"}

_EXPECTED_CRITICAL = 1
_EXPECTED_WAIVED = 1
# ``requests`` is a pypi package, so the language map the stats fold is handed can cover it.
_EXPECTED_COVERABLE = 1

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/{_COMPONENT}@{_VERSION}",
            "name": _COMPONENT,
            "version": _VERSION,
            "purl": f"pkg:pypi/{_COMPONENT}@{_VERSION}",
            "licenses": [{"license": {"id": _LICENSE}}],
        }
    ],
}

# A container SBOM: the parser reads ``alpine:3.18`` out of the metadata component as the
# source target, and the OS purl routes the advisory to the base-image recommendation.
_IMAGE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"type": "container", "name": _IMAGE_NAME, "version": _IMAGE_TAG}},
    "components": [
        {
            "type": "library",
            "bom-ref": f"pkg:apk/{_OS_COMPONENT}@{_OS_VERSION}",
            "name": _OS_COMPONENT,
            "version": _OS_VERSION,
            "purl": f"pkg:apk/{_OS_COMPONENT}@{_OS_VERSION}",
        }
    ],
}


class _FakeOsv:
    """One fixable critical advisory per parsed component, in the shape ``normalize_osv`` reads."""

    name = _OSV

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {
            "osv_vulnerabilities": [
                {
                    "component": component["name"],
                    "version": component["version"],
                    "vulnerabilities": [
                        {
                            "id": _CVE,
                            "severity": _SEVERITY_CRITICAL,
                            "summary": _SUMMARY,
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": _FIXED_VERSION}],
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                }
                for component in parsed_components or []
            ]
        }


@pytest.fixture
def _osv(monkeypatch):

    serve_analyzer(monkeypatch, _OSV, _FakeOsv())


def _request(**overrides) -> AdhocAnalyzeRequest:
    fields = {"sboms": [_SBOM], "analyzers": [_OSV], "apply_global_waivers": False}
    fields.update(overrides)
    return AdhocAnalyzeRequest(**fields)


def _recommendations_of_type(response, recommendation_type) -> list[dict]:
    return [rec for rec in response.recommendations if rec["type"] == recommendation_type]


@pytest.mark.asyncio
async def test_stats_count_the_findings(_osv):
    response = await run_adhoc_analysis(_request(), FakeDatabase())

    assert response.stats.critical == _EXPECTED_CRITICAL
    assert response.stats.risk_score > 0.0
    # The same language map the reachability stage was handed reaches the fold.
    assert response.stats.reachability.coverable_count == _EXPECTED_COVERABLE


@pytest.mark.asyncio
async def test_waived_findings_do_not_reach_the_stats(_osv):
    db = FakeDatabase()
    waiver = Waiver(project_id=None, reason=_REASON, created_by=_CREATED_BY, vulnerability_id=_CVE)
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))

    response = await run_adhoc_analysis(_request(apply_global_waivers=True), db)

    assert response.waived_count == _EXPECTED_WAIVED
    assert response.stats.critical == 0
    assert response.findings[0]["waived"] is True, "the waived finding is still reported, just not counted"


@pytest.mark.asyncio
async def test_a_waived_finding_generates_no_work_to_do(_osv):
    db = FakeDatabase()
    waiver = Waiver(project_id=None, reason=_REASON, created_by=_CREATED_BY, vulnerability_id=_CVE)
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))

    response = await run_adhoc_analysis(_request(apply_global_waivers=True), db)

    assert _recommendations_of_type(response, _DIRECT_DEPENDENCY_UPDATE) == []


@pytest.mark.asyncio
async def test_recommendations_are_serialised_dicts(_osv):
    response = await run_adhoc_analysis(_request(), FakeDatabase())

    updates = _recommendations_of_type(response, _DIRECT_DEPENDENCY_UPDATE)
    assert len(updates) == 1
    assert _RECOMMENDATION_KEYS <= set(updates[0])
    assert updates[0]["action"]["target_version"] == _FIXED_VERSION


@pytest.mark.asyncio
async def test_the_image_the_sbom_names_reaches_the_recommendation(_osv):
    """Pins both the source target and the dependency rows: without the rows the advisory is
    classified as an application dependency and no base-image recommendation exists at all."""
    response = await run_adhoc_analysis(_request(sboms=[_IMAGE_SBOM]), FakeDatabase())

    base_image = _recommendations_of_type(response, _BASE_IMAGE_UPDATE)
    assert len(base_image) == 1
    assert base_image[0]["action"]["current_image"] == _SOURCE_TARGET


@pytest.mark.asyncio
async def test_dependency_enrichments_are_returned_not_persisted(_osv):
    db = FakeDatabase()

    response = await run_adhoc_analysis(_request(analyzers=[_OSV, _LICENSE_COMPLIANCE]), db)

    assert len(response.dependencies) == 1
    enrichment = response.dependencies[0]
    assert set(enrichment) == _ENRICHMENT_KEYS
    assert enrichment["name"] == _COMPONENT
    assert enrichment["version"] == _VERSION
    assert enrichment["data"]["license"] == _LICENSE
    assert enrichment["data"]["license_category"] == _LICENSE_CATEGORY

    assert await db.dependency_enrichments.count_documents({}) == 0
    assert await db.dependencies.count_documents({}) == 0
