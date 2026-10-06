"""How the ad-hoc EPSS/KEV stage reports what the enrichment did and where it reached."""

from unittest.mock import AsyncMock

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.enrichment.service import vulnerability_enrichment_service
from tests.helpers.analyzers import serve_analyzer
from tests.helpers.enrichment import Upstreams, serve_enrichment
from tests.mocks.fake_mongo import FakeDatabase

_ENRICHMENT = "epss_kev"
_NO_VULNERABILITIES = "no vulnerability findings"
_TRUFFLEHOG_NAME = "trufflehog"
_FEED_DOWN = "EPSS feed down"
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


def _serve(monkeypatch, **mock) -> AsyncMock:
    enrich = AsyncMock(**{"return_value": ({}, []), **mock})
    monkeypatch.setattr(vulnerability_enrichment_service, "enrich_findings", enrich)
    return enrich


def _vulnerable_osv(*vulnerabilities: dict) -> object:
    class _Osv:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            return {
                "osv_vulnerabilities": [
                    {"component": _VULNERABLE_COMPONENT, "version": "2.31.0", "vulnerabilities": list(vulnerabilities)}
                ]
            }

    return _Osv()


def _secrets_request() -> AdhocAnalyzeRequest:
    return AdhocAnalyzeRequest(scanners={_TRUFFLEHOG_NAME: _TRUFFLEHOG}, analyzers=[], apply_global_waivers=False)


def _vulnerable_request(monkeypatch, *analyzers: str) -> AdhocAnalyzeRequest:
    serve_analyzer(monkeypatch, "osv", _vulnerable_osv({"id": _CVE, "severity": "HIGH", "summary": "example"}))
    return AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv", *analyzers], apply_global_waivers=False)


@pytest.mark.asyncio
async def test_enrichment_failure_is_reported(monkeypatch):
    _serve(monkeypatch, side_effect=RuntimeError(_FEED_DOWN))

    response = await run_adhoc_analysis(_vulnerable_request(monkeypatch), FakeDatabase())

    assert response.analyzers.errored[_ENRICHMENT] == [_FEED_DOWN]
    assert _ENRICHMENT not in response.analyzers.ran


@pytest.mark.asyncio
async def test_an_unreadable_source_reports_the_stage_as_errored(monkeypatch):
    _serve(monkeypatch, return_value=({}, ["KEV"]))

    response = await run_adhoc_analysis(_vulnerable_request(monkeypatch), FakeDatabase())

    assert response.analyzers.errored[_ENRICHMENT] == ["KEV unavailable"]
    assert _ENRICHMENT not in response.analyzers.ran


@pytest.mark.asyncio
async def test_a_run_without_vulnerability_findings_skips_the_stage_and_sends_nothing(monkeypatch):
    enrich = _serve(monkeypatch)

    response = await run_adhoc_analysis(_secrets_request(), FakeDatabase())

    enrich.assert_not_awaited()
    assert response.analyzers.skipped[_ENRICHMENT] == _NO_VULNERABILITIES
    assert _ENRICHMENT not in response.analyzers.ran
    assert _ENRICHMENT not in response.analyzers.notes
    assert response.epss_kev_summary["total_vulnerabilities"] == 0


@pytest.mark.asyncio
async def test_naming_the_stage_does_not_report_it_as_both_run_and_skipped(monkeypatch):
    _serve(monkeypatch)

    response = await run_adhoc_analysis(_vulnerable_request(monkeypatch, _ENRICHMENT), FakeDatabase())

    assert _ENRICHMENT in response.analyzers.ran
    assert _ENRICHMENT not in response.analyzers.skipped


@pytest.mark.asyncio
async def test_only_vulnerability_records_are_handed_to_the_service(monkeypatch):
    serve_analyzer(monkeypatch, "osv", _vulnerable_osv({"id": _CVE, "severity": "HIGH", "summary": "example"}))
    enrich = _serve(monkeypatch)

    request = AdhocAnalyzeRequest(
        sboms=[_SBOM],
        scanners={_TRUFFLEHOG_NAME: _TRUFFLEHOG},
        analyzers=["osv"],
        apply_global_waivers=False,
    )
    response = await run_adhoc_analysis(request, FakeDatabase())

    handed = enrich.await_args.args[0]
    assert [record["component"] for record in handed] == [_VULNERABLE_COMPONENT]
    assert response.epss_kev_summary["total_vulnerabilities"] == 1
    # The secret finding is still returned; it is only kept out of the enrichment batch.
    assert len(response.findings) == 2


@pytest.mark.asyncio
async def test_the_kev_card_names_the_bundled_cve_the_enrichment_marks(monkeypatch):
    from app.schemas.enrichment import VulnerabilityEnrichment
    from app.schemas.recommendation import RecommendationType
    from app.services.enrichment.service import apply_enrichments

    first, second = "CVE-2023-0001", "CVE-2023-0002"
    live = {
        first: VulnerabilityEnrichment(cve=first, risk_score=20.0),
        second: VulnerabilityEnrichment(cve=second, risk_score=40.0, is_kev=True),
    }

    async def enrich_findings(findings):
        for finding in findings:
            apply_enrichments(finding["details"], live)
        return live, []

    advisory = {"id": "ALAS2-2023-2001", "aliases": [first, second], "severity": "HIGH", "summary": "s"}
    serve_analyzer(monkeypatch, "osv", _vulnerable_osv(advisory))
    _serve(monkeypatch, side_effect=enrich_findings)

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    [kev_card] = [r for r in response.recommendations if r["type"] == RecommendationType.KNOWN_EXPLOIT]
    assert kev_card["action"]["cves"] == [second]


@pytest.mark.asyncio
async def test_the_note_names_every_host_the_enrichment_reached(fake_cache, monkeypatch):
    ghsa_id = "GHSA-jfh8-c2jp-5v3q"
    serve_analyzer(monkeypatch, "osv", _vulnerable_osv({"id": ghsa_id, "severity": "HIGH", "summary": "s"}))
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams(advisories={ghsa_id: _CVE}, kev=(_CVE,)))

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    contacted = {r.url.host for r in seen}
    assert contacted == {"api.github.com", "api.first.org", "www.cisa.gov"}
    assert all(host in response.analyzers.notes[_ENRICHMENT] for host in contacted)
