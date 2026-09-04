"""Stateless ad-hoc orchestrator."""

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocLicensePolicy
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.analysis.registry import analyzers
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
_UNKNOWN_ANALYZER = "unknown analyzer"
_TRUFFLEHOG_NAME = "trufflehog"
_CRYPTO_ANALYZER = "crypto_weak_algorithm"
_EMPTY_PAYLOAD = "empty payload"
_SERIAL_NUMBER = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
_FIRST_SBOM_SOURCE = "SBOM #1"
_THIRD_SBOM_SOURCE = "SBOM #3"
_NO_COMPONENTS = "no components could be parsed"
_DROPPED_COMPONENTS = "component(s) dropped by the parser"
_UNRECOGNISED_PAYLOAD = "unrecognised payload shape"
_HEALTHY_COMPONENTS = 201

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

# Shapes a caller reaches this endpoint with by accident: an error body, a wrapper around the
# real document, and the right format with the component list misspelled.
_UNREADABLE_SBOMS = [
    {"detail": "Not Found"},
    {"hello": "world"},
    {"sbom": _SBOM},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "component": _SBOM["components"]},
]

# Scanner-native report shapes, one level inside the envelope the schema documents.
_UNREADABLE_SCANNER_PAYLOADS = [
    ("bearer", {"critical": [{"id": "x", "title": "t", "filename": "f.py", "line_number": 1}]}),
    ("kics", {"total_counter": 7}),
    ("trufflehog", {"results": [{"DetectorType": 8, "Raw": "AKIAIOSFODNN7EXAMPLE", "Verified": True}]}),
]

# The parser caps nesting; a component below the cap is dropped rather than analysed.
_DEEPLY_NESTED_COMPONENT: dict = {"type": "library", "name": "deep", "version": "1.0.0"}
_LEAF = _DEEPLY_NESTED_COMPONENT
for _ in range(150):
    _LEAF["components"] = [{"type": "library", "name": "nested", "version": "1.0.0"}]
    _LEAF = _LEAF["components"][0]
_LEAF["licenses"] = [{"license": {"id": "GPL-3.0-only"}}]

_PARTLY_MALFORMED_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": ["a string", 42, None, *_SBOM["components"]],
}

# One unusable sub-field alongside 201 healthy components: the graph builders, unlike the
# component loop, do not tolerate a non-list ``dependsOn``.
_ONE_BAD_SUBFIELD_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/c{index}@1.0.0",
            "name": f"c{index}",
            "version": "1.0.0",
            "purl": f"pkg:pypi/c{index}@1.0.0",
            "licenses": [{"license": {"id": "GPL-3.0-only"}}],
        }
        for index in range(_HEALTHY_COMPONENTS)
    ],
    "dependencies": [{"ref": "pkg:pypi/c0@1.0.0", "dependsOn": None}],
}

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

    assert response.analyzers.skipped[_UNKNOWN_NAME] == _UNKNOWN_ANALYZER
    # Every registered analyzer the request left out is accounted for alongside it.
    assert set(response.analyzers.skipped) == set(analyzers) | {_UNKNOWN_NAME}
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

    assert response.analyzers.errored == {"osv": [f"{_FIRST_SBOM_SOURCE}: {_ANALYZER_ERROR}"]}
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

    assert response.analyzers.errored == {"osv": [f"{_FIRST_SBOM_SOURCE}: {_ANALYZER_TIMEOUT}"]}
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
    assert set(response.analyzers.skipped) == set(analyzers)
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

    assert response.analyzers.errored == {"trufflehog": [_ANALYZER_TIMEOUT]}
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_empty_posted_payload_is_skipped_rather_than_reported_as_ran():
    request = AdhocAnalyzeRequest(scanners={"trufflehog": {}}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.skipped[_TRUFFLEHOG_NAME] == _EMPTY_PAYLOAD
    assert set(response.analyzers.skipped) == set(analyzers) | {_TRUFFLEHOG_NAME}
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

    assert response.analyzers.errored == {"osv": [f"{_FIRST_SBOM_SOURCE}: "]}
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

    assert response.analyzers.errored == {"osv": [f"{_SECOND_SBOM_SOURCE}: {_ANALYZER_ERROR}"]}
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


@pytest.mark.asyncio
@pytest.mark.parametrize("sbom", _UNREADABLE_SBOMS)
async def test_an_sbom_nothing_could_be_read_from_is_not_reported_as_a_clean_run(sbom):
    request = AdhocAnalyzeRequest(sboms=[sbom], analyzers=["license_compliance"], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert _NO_COMPONENTS in response.analyzers.skipped_inputs[_SBOM_LABEL]
    assert response.analyzers.ran == []
    assert response.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("scanner", "payload"), _UNREADABLE_SCANNER_PAYLOADS)
async def test_a_scanner_payload_shape_the_normalizer_cannot_read_is_not_reported_as_ran(scanner, payload):
    request = AdhocAnalyzeRequest(scanners={scanner: payload}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert _UNRECOGNISED_PAYLOAD in response.analyzers.errored[scanner][0]
    assert response.analyzers.ran == []
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_a_scanner_payload_that_genuinely_found_nothing_still_counts_as_ran():
    request = AdhocAnalyzeRequest(scanners={"trufflehog": {"findings": []}}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.ran == ["trufflehog"]
    assert response.analyzers.errored == {}


@pytest.mark.asyncio
async def test_components_the_parser_dropped_are_reported():
    request = AdhocAnalyzeRequest(
        sboms=[_PARTLY_MALFORMED_SBOM], analyzers=["license_compliance"], apply_global_waivers=False
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert _DROPPED_COMPONENTS in response.analyzers.skipped_inputs[_SBOM_LABEL]
    assert "license_compliance" in response.analyzers.ran
    assert [f["id"] for f in _findings_of_type(response, _TYPE_LICENSE)] == [_LICENSE_FINDING_ID]


@pytest.mark.asyncio
async def test_a_component_routed_to_crypto_assets_is_not_reported_as_dropped():
    crypto_only = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "algo-sha1",
                "name": "SHA-1",
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
            }
        ],
    }
    request = AdhocAnalyzeRequest(sboms=[crypto_only], analyzers=[_CRYPTO_ANALYZER], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    # An empty ``skipped_inputs`` is what proves the asset was read: an SBOM the parser got
    # nothing out of is reported there instead.
    assert response.analyzers.skipped_inputs == {}
    assert response.analyzers.ran == []


@pytest.mark.asyncio
async def test_one_malformed_sub_field_rejects_the_whole_input_and_says_so():
    request = AdhocAnalyzeRequest(
        sboms=[_ONE_BAD_SUBFIELD_SBOM], analyzers=["license_compliance"], apply_global_waivers=False
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.skipped_inputs[_SBOM_LABEL].startswith("could not be parsed:")
    assert response.analyzers.ran == []
    assert response.findings == []


@pytest.mark.asyncio
async def test_every_failure_reason_is_kept_and_attributed_to_its_input(monkeypatch):
    from app.services.analysis import registry

    class _Flaky:
        name = "osv"

        def __init__(self):
            self.calls = 0

        async def analyze(self, sbom, settings=None, parsed_components=None):
            self.calls += 1
            if self.calls == 2:
                return {"osv_vulnerabilities": []}
            raise RuntimeError(f"{_ANALYZER_ERROR} {self.calls}")

    monkeypatch.setitem(registry.analyzers, "osv", _Flaky())

    request = AdhocAnalyzeRequest(sboms=[_SBOM, _SBOM, _SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {
        "osv": [f"{_FIRST_SBOM_SOURCE}: {_ANALYZER_ERROR} 1", f"{_THIRD_SBOM_SOURCE}: {_ANALYZER_ERROR} 3"]
    }
    assert response.analyzers.ran == []


@pytest.mark.asyncio
async def test_a_normalizer_that_cannot_read_an_analyzer_result_is_reported_not_raised(monkeypatch):
    from app.services.analysis import registry

    class _Reshaped:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            # The normalizers dereference analyzer output without type checks.
            return {"osv_vulnerabilities": [None]}

    monkeypatch.setitem(registry.analyzers, "osv", _Reshaped())

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert list(response.analyzers.errored) == ["osv"]
    assert response.analyzers.ran == []
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []
