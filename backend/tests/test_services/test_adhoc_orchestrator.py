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
_EMPTY_PAYLOAD = "empty payload"
_SERIAL_NUMBER = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
_FIRST_SBOM_SOURCE = "SBOM #1"

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

# A scanner version that reshapes a list into a map, or drops a nested object, reaches the
# normalizers as caller-controlled data they were never written to defend against.
_MALFORMED_SCANNER_PAYLOADS = [
    ("trufflehog", {"findings": "no"}),
    ("trufflehog", {"findings": [None]}),
    ("opengrep", {"findings": [{"check_id": "x", "path": "p", "start": "12", "extra": {"severity": 3}}]}),
    ("bearer", {"findings": [{"id": "x", "line_number": "44", "severity": 3, "filename": None}]}),
    ("kics", {"queries": {"first": {}}}),
    ("kics", {"queries": [{"query_name": "q", "files": "deploy/pod.yaml"}]}),
]

# An explicit null name is a present key, so a dict default never fires.
_NULL_NAMED_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": _SERIAL_NUMBER,
    "metadata": {"component": {"name": None}},
    "components": _SBOM["components"],
}
_ANONYMOUS_SBOM = {k: v for k, v in _NULL_NAMED_SBOM.items() if k != "serialNumber"}


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


@pytest.mark.asyncio
@pytest.mark.parametrize(("scanner", "payload"), _MALFORMED_SCANNER_PAYLOADS)
async def test_malformed_posted_scanner_output_is_reported_not_raised(scanner, payload):
    request = AdhocAnalyzeRequest(scanners={scanner: payload}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert scanner in response.analyzers.errored
    assert response.analyzers.ran == []
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_error_shaped_posted_payload_is_reported_not_turned_into_a_system_warning():
    request = AdhocAnalyzeRequest(
        scanners={"trufflehog": {"error": _ANALYZER_TIMEOUT}}, analyzers=[], apply_global_waivers=False
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"trufflehog": _ANALYZER_TIMEOUT}
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_empty_posted_payload_is_skipped_rather_than_reported_as_ran():
    request = AdhocAnalyzeRequest(scanners={"trufflehog": {}}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.skipped == {"trufflehog": _EMPTY_PAYLOAD}
    assert response.analyzers.ran == []


@pytest.mark.asyncio
async def test_blank_error_string_is_reported_not_aggregated(monkeypatch):
    from app.services.analysis import registry

    class _Blank:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            return {"error": ""}

    monkeypatch.setitem(registry.analyzers, "osv", _Blank())

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"osv": ""}
    assert response.analyzers.ran == []
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_an_analyzer_that_failed_on_one_sbom_is_not_also_reported_as_ran(monkeypatch):
    from app.services.analysis import registry

    class _Flaky:
        name = "osv"

        def __init__(self):
            self.calls = 0

        async def analyze(self, sbom, settings=None, parsed_components=None):
            self.calls += 1
            if self.calls == 1:
                return {"vulnerabilities": []}
            raise RuntimeError(_ANALYZER_ERROR)

    monkeypatch.setitem(registry.analyzers, "osv", _Flaky())

    request = AdhocAnalyzeRequest(sboms=[_SBOM, _SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"osv": _ANALYZER_ERROR}
    assert response.analyzers.ran == []


@pytest.mark.asyncio
async def test_a_null_metadata_name_falls_back_to_the_serial_number():
    request = AdhocAnalyzeRequest(
        sboms=[_NULL_NAMED_SBOM], analyzers=["license_compliance"], apply_global_waivers=False
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert [f["found_in"] for f in _findings_of_type(response, _TYPE_LICENSE)] == [[_SERIAL_NUMBER]]


@pytest.mark.asyncio
async def test_a_null_metadata_name_without_a_serial_number_falls_back_to_the_position():
    request = AdhocAnalyzeRequest(sboms=[_ANONYMOUS_SBOM], analyzers=["license_compliance"], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert [f["found_in"] for f in _findings_of_type(response, _TYPE_LICENSE)] == [[_FIRST_SBOM_SOURCE]]
