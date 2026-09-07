"""Stateless ad-hoc orchestrator."""

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocLicensePolicy
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.analysis.registry import analyzer_factories
from tests.mocks.fake_mongo import FakeDatabase
from tests.helpers.analyzers import serve_analyzer

_SECRET_FILE = "app/config.py"
_SBOM_LABEL = "sbom#1"
_LICENSE_FINDING_ID = "LIC-GPL-3.0-only"
_SEVERITY_HIGH = "HIGH"
_SEVERITY_INFO = "INFO"
_TYPE_SECRET = "secret"
_TYPE_LICENSE = "license"
_TYPE_VULNERABILITY = "vulnerability"
_TYPE_SYSTEM_WARNING = "system_warning"
_PARTIAL_COVERAGE = "partial coverage"
_COMPONENTS_NOT_SCANNED = "{count} component(s) were not scanned"
_RECORDS_NOT_FETCHED = "{count} vulnerability record(s) could not be fetched"
_SKIPPED_COMPONENTS = 7
_PARTIAL_CVE = "CVE-2024-12345"
_EXPECTED_SECRET_FINDINGS = 1
_ANALYZER_ERROR = "upstream exploded"
_ANALYZER_TIMEOUT = "timed out after 60s"
_UNKNOWN_NAME = "not_a_scanner"
_UNKNOWN_ANALYZER = "unknown analyzer"
_TRUFFLEHOG_NAME = "trufflehog"
_OSV_NAME = "osv"
_OSV_UPSTREAM = "api.osv.dev"
_CRYPTO_ANALYZER = "crypto_weak_algorithm"
# The stage that evaluates the crypto rules; it reports itself as skipped for an SBOM
# carrying no cryptographic-asset components.
_CRYPTO_RULES = "crypto_rules"
# The enrichment stage runs on every request and is reported last.
_ENRICHMENT = "epss_kev"
# Reachability needs a callgraph none of these requests posts, so it reports itself as skipped.
_REACHABILITY = "reachability"
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

_KICS_QUERIES_WITHOUT_FILES = 200
_TRUFFLEHOG_LOWERCASE_KEYS = 5000
_ONE_UNREADABLE_OF_TWO = "1 of 2"

# The container each normalizer reads, filled with entries it cannot: a KICS report whose queries
# carry no hits, and a TruffleHog version that lowercased its field names.
_WRONG_SHAPED_ENTRIES = [
    (
        "kics",
        {
            "queries": [
                {"query_name": f"q{i}", "query_id": f"id{i}", "severity": "HIGH"}
                for i in range(_KICS_QUERIES_WITHOUT_FILES)
            ]
        },
        "files",
    ),
    (
        "trufflehog",
        {"findings": [{"detectortype": "AWS", "raw": f"secret{i}"} for i in range(_TRUFFLEHOG_LOWERCASE_KEYS)]},
        "DetectorType",
    ),
    (
        "opengrep",
        {"findings": [{"check_id": "python.rule.0", "path": _SECRET_FILE, "start": {"line": 1}}]},
        "end",
    ),
    # Bearer groups its findings under a severity key, so the entry check has to reach inside it.
    (
        "bearer",
        {"findings": {"critical": [{"detector": "AWS", "raw": "AKIAIOSFODNN7EXAMPLE"}]}},
        "id",
    ),
    (
        "bearer",
        {"findings": [{"detector": "AWS", "raw": "AKIAIOSFODNN7EXAMPLE"}]},
        "id",
    ),
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
    assert response.analyzers.ran == [_TRUFFLEHOG_NAME, _ENRICHMENT]


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
    assert set(response.analyzers.skipped) == set(analyzer_factories) | {_UNKNOWN_NAME, _REACHABILITY, _CRYPTO_RULES}
    assert response.analyzers.ran == [_ENRICHMENT]


@pytest.mark.asyncio
async def test_failing_analyzer_is_reported_and_not_turned_into_a_system_warning(monkeypatch):

    class _Boom:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            raise RuntimeError(_ANALYZER_ERROR)

    serve_analyzer(monkeypatch, "osv", _Boom())

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"osv": [f"{_FIRST_SBOM_SOURCE}: {_ANALYZER_ERROR}"]}
    assert "osv" not in response.analyzers.ran
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_error_shaped_analyzer_result_is_reported_not_aggregated(monkeypatch):

    class _Timeout:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            return {"error": _ANALYZER_TIMEOUT, "vulnerabilities": []}

    serve_analyzer(monkeypatch, "osv", _Timeout())

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
    assert set(response.analyzers.skipped) == set(analyzer_factories) | {_REACHABILITY, _CRYPTO_RULES}
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
    assert response.analyzers.ran == [_ENRICHMENT]
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []
    assert response.findings == [], "a payload reported as errored must not also contribute findings"


def _opengrep_item(index: int) -> dict:
    return {
        "check_id": f"python.rule.{index}",
        "path": _SECRET_FILE,
        "start": {"line": index + 1},
        "end": {"line": index + 1},
        "extra": {"severity": "ERROR", "message": "eval() detected"},
    }


# The normalizer reads the list in order, so where the unreadable item sits decides how much
# of the payload it accepted before it gave up.
_UNREADABLE_FIRST = [None, _opengrep_item(0), _opengrep_item(1)]
_UNREADABLE_LAST = [_opengrep_item(0), _opengrep_item(1), None]


@pytest.mark.asyncio
@pytest.mark.parametrize("items", [_UNREADABLE_FIRST, _UNREADABLE_LAST])
async def test_where_the_unreadable_item_sits_does_not_change_the_result(items):
    request = AdhocAnalyzeRequest(scanners={"opengrep": {"findings": items}}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert list(response.analyzers.errored) == ["opengrep"]
    assert response.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("scanner", "payload", "field"), _WRONG_SHAPED_ENTRIES)
async def test_entries_the_normalizer_cannot_read_are_not_reported_as_coverage(scanner, payload, field):
    """The container is the shape the endpoint documents and the entries in it are not, so the
    run normalises to nothing and would otherwise answer with an unqualified all-clear."""
    request = AdhocAnalyzeRequest(scanners={scanner: payload}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert scanner not in response.analyzers.ran
    assert field in response.analyzers.errored[scanner][0]
    assert response.findings == []
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_the_shortfall_counts_the_unreadable_entries_against_the_posted_ones():
    payload = {"findings": [_TRUFFLEHOG["findings"][0], {"Raw": "no detector"}]}
    request = AdhocAnalyzeRequest(scanners={_TRUFFLEHOG_NAME: payload}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored[_TRUFFLEHOG_NAME] == [
        f"{_ONE_UNREADABLE_OF_TWO} 'findings' entries could not be read (DetectorType: Field required)"
    ]


@pytest.mark.asyncio
async def test_entries_that_dedup_to_one_finding_are_still_full_coverage():
    """The same secret twice in one file is one finding by design, so comparing entry count to
    finding count would report a shortfall on a payload the pipeline read completely."""
    payload = {"findings": [_TRUFFLEHOG["findings"][0], dict(_TRUFFLEHOG["findings"][0])]}
    request = AdhocAnalyzeRequest(scanners={_TRUFFLEHOG_NAME: payload}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {}
    assert _TRUFFLEHOG_NAME in response.analyzers.ran
    assert len(_findings_of_type(response, _TYPE_SECRET)) == _EXPECTED_SECRET_FINDINGS


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
    assert set(response.analyzers.skipped) == set(analyzer_factories) | {_TRUFFLEHOG_NAME, _REACHABILITY, _CRYPTO_RULES}
    assert response.analyzers.ran == [_ENRICHMENT]


@pytest.mark.asyncio
async def test_blank_error_string_is_reported_not_aggregated(monkeypatch):

    class _Blank:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            return {"error": ""}

    serve_analyzer(monkeypatch, "osv", _Blank())

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"osv": [f"{_FIRST_SBOM_SOURCE}: "]}
    assert response.analyzers.ran == [_ENRICHMENT]
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_an_analyzer_that_failed_on_one_sbom_is_not_also_reported_as_ran(monkeypatch):

    class _Flaky:
        name = "osv"

        def __init__(self):
            self.calls = 0

        async def analyze(self, sbom, settings=None, parsed_components=None):
            self.calls += 1
            if self.calls == 1:
                return {"vulnerabilities": []}
            raise RuntimeError(_ANALYZER_ERROR)

    serve_analyzer(monkeypatch, "osv", _Flaky())

    request = AdhocAnalyzeRequest(sboms=[_SBOM, _SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {"osv": [f"{_SECOND_SBOM_SOURCE}: {_ANALYZER_ERROR}"]}
    assert response.analyzers.ran == [_ENRICHMENT]


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
    assert response.analyzers.ran == [_ENRICHMENT]
    assert response.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("scanner", "payload"), _UNREADABLE_SCANNER_PAYLOADS)
async def test_a_scanner_payload_shape_the_normalizer_cannot_read_is_not_reported_as_ran(scanner, payload):
    request = AdhocAnalyzeRequest(scanners={scanner: payload}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert _UNRECOGNISED_PAYLOAD in response.analyzers.errored[scanner][0]
    assert response.analyzers.ran == [_ENRICHMENT]
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


class _FakeOsv:
    name = _OSV_NAME

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {"osv_vulnerabilities": []}


class _BrokenOsv:
    name = _OSV_NAME

    async def analyze(self, sbom, settings=None, parsed_components=None):
        raise RuntimeError(_ANALYZER_ERROR)


@pytest.mark.asyncio
@pytest.mark.parametrize("analyzer", [_FakeOsv(), _BrokenOsv()])
async def test_the_stages_that_left_the_process_are_named_whether_or_not_they_succeeded(monkeypatch, analyzer):
    """Storing nothing is not sending nothing, and a failed upstream call still sent the query."""

    serve_analyzer(monkeypatch, _OSV_NAME, analyzer)
    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_OSV_NAME], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert set(response.analyzers.notes) == {_OSV_NAME, _ENRICHMENT}
    assert _OSV_UPSTREAM in response.analyzers.notes[_OSV_NAME]


@pytest.mark.asyncio
async def test_an_analyzer_that_never_ran_is_not_named_in_the_notes():
    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["license_compliance"], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert set(response.analyzers.notes) == {_ENRICHMENT}


@pytest.mark.asyncio
async def test_a_scanner_payload_that_genuinely_found_nothing_still_counts_as_ran():
    request = AdhocAnalyzeRequest(scanners={"trufflehog": {"findings": []}}, analyzers=[], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.ran == [_TRUFFLEHOG_NAME, _ENRICHMENT]
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
    # The routed asset is what the crypto stage evaluates, so it reports itself as having run.
    assert response.analyzers.ran == [_CRYPTO_RULES, _ENRICHMENT]


@pytest.mark.asyncio
async def test_one_malformed_sub_field_rejects_the_whole_input_and_says_so():
    request = AdhocAnalyzeRequest(
        sboms=[_ONE_BAD_SUBFIELD_SBOM], analyzers=["license_compliance"], apply_global_waivers=False
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.skipped_inputs[_SBOM_LABEL].startswith("could not be parsed:")
    assert response.analyzers.ran == [_ENRICHMENT]
    assert response.findings == []


@pytest.mark.asyncio
async def test_every_failure_reason_is_kept_and_attributed_to_its_input(monkeypatch):

    class _Flaky:
        name = "osv"

        def __init__(self):
            self.calls = 0

        async def analyze(self, sbom, settings=None, parsed_components=None):
            self.calls += 1
            if self.calls == 2:
                return {"osv_vulnerabilities": []}
            raise RuntimeError(f"{_ANALYZER_ERROR} {self.calls}")

    serve_analyzer(monkeypatch, "osv", _Flaky())

    request = AdhocAnalyzeRequest(sboms=[_SBOM, _SBOM, _SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.errored == {
        "osv": [f"{_FIRST_SBOM_SOURCE}: {_ANALYZER_ERROR} 1", f"{_THIRD_SBOM_SOURCE}: {_ANALYZER_ERROR} 3"]
    }
    assert response.analyzers.ran == [_ENRICHMENT]


@pytest.mark.asyncio
async def test_a_normalizer_that_cannot_read_an_analyzer_result_is_reported_not_raised(monkeypatch):

    class _Reshaped:
        name = "osv"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            # The normalizers dereference analyzer output without type checks.
            return {"osv_vulnerabilities": [None]}

    serve_analyzer(monkeypatch, "osv", _Reshaped())

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=["osv"], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert list(response.analyzers.errored) == ["osv"]
    assert response.analyzers.ran == [_ENRICHMENT]
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


def _partial_osv(monkeypatch, result):

    class _Partial:
        name = _OSV_NAME

        async def analyze(self, sbom, settings=None, parsed_components=None):
            return result

    serve_analyzer(monkeypatch, _OSV_NAME, _Partial())


@pytest.mark.parametrize(
    ("result_key", "expected"),
    [
        ("partial_components_skipped", _COMPONENTS_NOT_SCANNED),
        ("partial_vulnerabilities_unhydrated", _RECORDS_NOT_FETCHED),
    ],
)
@pytest.mark.asyncio
async def test_an_analyzer_that_covered_only_part_of_its_input_is_not_reported_as_ran(
    monkeypatch, result_key, expected
):
    """An unreachable CVE source answers a vulnerable SBOM with zero findings; the caller has to
    be able to tell that from a clean bill of health."""
    _partial_osv(monkeypatch, {"osv_vulnerabilities": [], result_key: _SKIPPED_COMPONENTS})

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_OSV_NAME], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    assert _OSV_NAME not in response.analyzers.ran
    assert response.analyzers.errored == {
        _OSV_NAME: [f"{_FIRST_SBOM_SOURCE}: {_PARTIAL_COVERAGE}: {expected.format(count=_SKIPPED_COMPONENTS)}"]
    }
    # Trap 4: the engine surfaces the same gap through the aggregator, which would mint a HIGH
    # SYSTEM_WARNING finding on a path whose caller asked only for what it posted.
    assert _findings_of_type(response, _TYPE_SYSTEM_WARNING) == []


@pytest.mark.asyncio
async def test_what_a_partial_analyzer_did_find_is_still_returned(monkeypatch):
    _partial_osv(
        monkeypatch,
        {
            "osv_vulnerabilities": [
                {
                    "component": "requests",
                    "version": "2.31.0",
                    "vulnerabilities": [{"id": _PARTIAL_CVE, "severity": _SEVERITY_HIGH, "summary": "rce"}],
                }
            ],
            "partial_components_skipped": _SKIPPED_COMPONENTS,
        },
    )

    request = AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_OSV_NAME], apply_global_waivers=False)
    response = await run_adhoc_analysis(request, FakeDatabase())

    advisories = [
        entry["id"]
        for finding in _findings_of_type(response, _TYPE_VULNERABILITY)
        for entry in finding["details"]["vulnerabilities"]
    ]
    assert advisories == [_PARTIAL_CVE]
    assert list(response.analyzers.errored) == [_OSV_NAME]
