"""EPSS/KEV enrichment runs on a per-request service instance and is always closed."""

from unittest.mock import AsyncMock

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
from tests.mocks.fake_mongo import FakeDatabase

_ENRICHMENT = "epss_kev"
_TRUFFLEHOG_NAME = "trufflehog"
_SERVICE_ATTRIBUTE = "app.services.analysis.adhoc.VulnerabilityEnrichmentService"
_FEED_DOWN = "EPSS feed down"
_SHARED_SINGLETON_USED = "the shared singleton must not be used ad-hoc"
_SECRET_FILE = "app/config.py"
_CVE = "CVE-2024-0001"
_VULNERABLE_COMPONENT = "requests"

_TRUFFLEHOG = {
    "findings": [
        {
            "DetectorType": 8,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {"Data": {"Filesystem": {"file": _SECRET_FILE}}},
        }
    ]
}


_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"name": "demo-service", "version": "1.0.0"}},
    "components": [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/{_VULNERABLE_COMPONENT}@2.31.0",
            "name": _VULNERABLE_COMPONENT,
            "version": "2.31.0",
            "purl": f"pkg:pypi/{_VULNERABLE_COMPONENT}@2.31.0",
        }
    ],
}


class _SpyService:
    instances: list["_SpyService"] = []

    def __init__(self):
        self.enriched = None
        self.closed = False
        _SpyService.instances.append(self)

    async def enrich_findings(self, findings):
        self.enriched = findings

    async def close(self):
        self.closed = True


class _ExplodingService(_SpyService):
    async def enrich_findings(self, findings):
        raise RuntimeError(_FEED_DOWN)


@pytest.fixture(autouse=True)
def _reset_instances():
    _SpyService.instances = []
    yield
    _SpyService.instances = []


def _secrets_request() -> AdhocAnalyzeRequest:
    return AdhocAnalyzeRequest(scanners={_TRUFFLEHOG_NAME: _TRUFFLEHOG}, analyzers=[], apply_global_waivers=False)


@pytest.mark.asyncio
async def test_module_singleton_is_never_used(monkeypatch):
    import app.services.enrichment as enrichment_pkg

    monkeypatch.setattr(
        enrichment_pkg.vulnerability_enrichment_service,
        "enrich_findings",
        AsyncMock(side_effect=AssertionError(_SHARED_SINGLETON_USED)),
    )
    monkeypatch.setattr(_SERVICE_ATTRIBUTE, _SpyService)

    await run_adhoc_analysis(_secrets_request(), FakeDatabase())

    assert len(_SpyService.instances) == 1
    assert _SpyService.instances[0].closed is True


@pytest.mark.asyncio
async def test_enrichment_failure_is_reported_and_the_client_still_closes(monkeypatch):
    monkeypatch.setattr(_SERVICE_ATTRIBUTE, _ExplodingService)

    response = await run_adhoc_analysis(_secrets_request(), FakeDatabase())

    assert response.analyzers.errored[_ENRICHMENT] == [_FEED_DOWN]
    assert _ENRICHMENT not in response.analyzers.ran
    assert _ExplodingService.instances[0].closed is True


@pytest.mark.asyncio
async def test_summary_is_always_present(monkeypatch):
    monkeypatch.setattr(_SERVICE_ATTRIBUTE, _SpyService)

    response = await run_adhoc_analysis(_secrets_request(), FakeDatabase())

    assert response.epss_kev_summary["total_vulnerabilities"] == 0
    assert response.analyzers.ran[-1] == _ENRICHMENT


@pytest.mark.asyncio
async def test_naming_the_stage_does_not_report_it_as_both_run_and_skipped(monkeypatch):
    monkeypatch.setattr(_SERVICE_ATTRIBUTE, _SpyService)

    request = AdhocAnalyzeRequest(
        scanners={_TRUFFLEHOG_NAME: _TRUFFLEHOG}, analyzers=[_ENRICHMENT], apply_global_waivers=False
    )
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert _ENRICHMENT in response.analyzers.ran
    assert _ENRICHMENT not in response.analyzers.skipped


@pytest.mark.asyncio
async def test_only_vulnerability_records_are_handed_to_the_service(monkeypatch):
    from app.services.analysis import registry

    class _Vulnerable:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            return {
                "osv_vulnerabilities": [
                    {
                        "component": _VULNERABLE_COMPONENT,
                        "version": "2.31.0",
                        "vulnerabilities": [{"id": _CVE, "severity": "HIGH", "summary": "example"}],
                    }
                ]
            }

    monkeypatch.setitem(registry.analyzers, "osv", _Vulnerable())
    monkeypatch.setattr(_SERVICE_ATTRIBUTE, _SpyService)

    request = AdhocAnalyzeRequest(
        sboms=[_SBOM],
        scanners={_TRUFFLEHOG_NAME: _TRUFFLEHOG},
        analyzers=["osv"],
        apply_global_waivers=False,
    )
    response = await run_adhoc_analysis(request, FakeDatabase())

    handed = _SpyService.instances[0].enriched
    assert [record["component"] for record in handed] == [_VULNERABLE_COMPONENT]
    assert response.epss_kev_summary["total_vulnerabilities"] == 1
    # The secret finding is still returned; it is only kept out of the enrichment batch.
    assert len(response.findings) == 2
