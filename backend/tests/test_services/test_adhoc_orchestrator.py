"""Stateless ad-hoc orchestrator."""

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocLicensePolicy
from app.services.analysis.adhoc import run_adhoc_analysis
from tests.mocks.fake_mongo import FakeDatabase

_SECRET_FILE = "app/config.py"
_SBOM_LABEL = "sbom#1"
_LICENSE_FINDING_ID = "LIC-GPL-3.0-only"
_SEVERITY_HIGH = "HIGH"
_SEVERITY_INFO = "INFO"
_TYPE_SECRET = "secret"
_TYPE_LICENSE = "license"
_TYPE_SYSTEM_WARNING = "system_warning"
_EXPECTED_SECRET_FINDINGS = 1
_ANALYZER_ERROR = "upstream exploded"
_ANALYZER_TIMEOUT = "timed out after 60s"
_UNKNOWN_NAME = "not_a_scanner"

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"name": "demo-service", "version": "1.0.0"}},
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "licenses": [{"license": {"id": "GPL-3.0-only"}}],
        }
    ],
}

# ``metadata`` must be an object; a list makes the CycloneDX branch of the parser raise.
_UNPARSEABLE_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": []}

# Without a metadata component the finding's source falls back to the SBOM's position.
_UNNAMED_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": _SBOM["components"],
}
_SECOND_SBOM_SOURCE = "SBOM #2"

_TRUFFLEHOG = {
    "findings": [
        {
            "DetectorType": 8,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": _SECRET_FILE}}},
        }
    ]
}


def _findings_of_type(response, finding_type):
    return [f for f in response.findings if f["type"] == finding_type]


@pytest.mark.asyncio
async def test_posted_scanner_payload_becomes_a_finding():
    request = AdhocAnalyzeRequest(
        scanners={"trufflehog": _TRUFFLEHOG},
        analyzers=[],
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    secrets = _findings_of_type(response, _TYPE_SECRET)
    assert len(secrets) == _EXPECTED_SECRET_FINDINGS
    assert secrets[0]["component"] == _SECRET_FILE
    assert response.analyzers.ran == ["trufflehog"]


@pytest.mark.asyncio
async def test_requested_pure_analyzer_runs_and_is_reported():
    request = AdhocAnalyzeRequest(
        sboms=[_SBOM],
        analyzers=["license_compliance"],
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert "license_compliance" in response.analyzers.ran
    assert response.analyzers.errored == {}
    licenses = _findings_of_type(response, _TYPE_LICENSE)
    assert [f["id"] for f in licenses] == [_LICENSE_FINDING_ID]


@pytest.mark.asyncio
async def test_findings_carry_the_finding_id_alias():
    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["license_compliance"], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.findings
    assert all(f["finding_id"] == f["id"] for f in response.findings)


@pytest.mark.asyncio
async def test_request_license_policy_reaches_the_analyzer_as_plain_settings():
    request = AdhocAnalyzeRequest(
        sboms=[_SBOM],
        analyzers=["license_compliance"],
        apply_global_waivers=False,
        license_policy=AdhocLicensePolicy(allow_strong_copyleft=True),
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {}
    licenses = _findings_of_type(response, _TYPE_LICENSE)
    assert [f["severity"] for f in licenses] == [_SEVERITY_INFO]


@pytest.mark.asyncio
async def test_default_license_policy_still_grades_strong_copyleft():
    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["license_compliance"], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    licenses = _findings_of_type(response, _TYPE_LICENSE)
    assert [f["severity"] for f in licenses] == [_SEVERITY_HIGH]


@pytest.mark.asyncio
async def test_unknown_analyzer_name_is_reported_not_silently_dropped():
    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_UNKNOWN_NAME], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.skipped == {_UNKNOWN_NAME: "unknown analyzer"}
    assert response.analyzers.ran == []


@pytest.mark.asyncio
async def test_failing_analyzer_is_reported_and_not_turned_into_a_system_warning(monkeypatch):
    from app.services.analysis import registry

    class _Boom:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            raise RuntimeError(_ANALYZER_ERROR)

    monkeypatch.setitem(registry.analyzers, "osv", _Boom())

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"osv": _ANALYZER_ERROR}
    assert "osv" not in response.analyzers.ran
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_error_shaped_analyzer_result_is_reported_not_aggregated(monkeypatch):
    from app.services.analysis import registry

    class _Timeout:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            return {"error": _ANALYZER_TIMEOUT, "vulnerabilities": []}

    monkeypatch.setitem(registry.analyzers, "osv", _Timeout())

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"osv": _ANALYZER_TIMEOUT}
    assert "osv" not in response.analyzers.ran
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_unparseable_sbom_is_reported_without_aborting_the_run():
    request = AdhocAnalyzeRequest(
        sboms=[_UNPARSEABLE_SBOM],
        scanners={"trufflehog": _TRUFFLEHOG},
        analyzers=[],
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert _SBOM_LABEL in response.analyzers.skipped_inputs
    # ``skipped`` is keyed by analyzer name; an input label in there is unreadable for consumers.
    assert response.analyzers.skipped == {}
    assert len(_findings_of_type(response, _TYPE_SECRET)) == _EXPECTED_SECRET_FINDINGS


@pytest.mark.asyncio
async def test_a_parseable_sbom_after_an_unparseable_one_is_still_analyzed():
    request = AdhocAnalyzeRequest(
        sboms=[_UNPARSEABLE_SBOM, _SBOM],
        analyzers=["license_compliance"],
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert list(response.analyzers.skipped_inputs) == [_SBOM_LABEL]
    assert "license_compliance" in response.analyzers.ran
    assert [f["id"] for f in _findings_of_type(response, _TYPE_LICENSE)] == [_LICENSE_FINDING_ID]


@pytest.mark.asyncio
async def test_finding_source_names_the_posted_position_not_the_surviving_one():
    request = AdhocAnalyzeRequest(
        sboms=[_UNPARSEABLE_SBOM, _UNNAMED_SBOM],
        analyzers=["license_compliance"],
        apply_global_waivers=False,
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    licenses = _findings_of_type(response, _TYPE_LICENSE)
    assert [f["found_in"] for f in licenses] == [[_SECOND_SBOM_SOURCE]]
