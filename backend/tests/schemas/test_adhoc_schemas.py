"""Defaults and validation rules of the ad-hoc analyze request/response models."""

import pytest
from pydantic import ValidationError

from app.schemas.adhoc import (
    MAX_ADHOC_ANALYZERS,
    MAX_ADHOC_SBOMS,
    AdhocAnalyzeRequest,
    AdhocAnalyzeResponse,
    AnalyzerReport,
)
from app.schemas.project import LicensePolicySchema

_SBOM = {"bomFormat": "CycloneDX"}
_TRUFFLEHOG_PAYLOAD = {"findings": []}
_ANALYZER = "osv"
_SBOM_LABEL = "sbom#1"
_SKIP_REASON = "could not be parsed"
_EXTRA_FORBIDDEN = "extra_forbidden"
_ENUM_ERROR = "enum"
_MISSPELLED_OPTION = "aplly_global_waivers"
_MISSPELLED_SCANNER = "trufflehogg"
_MISSPELLED_POLICY_KEY = "deployment_modell"
_MISSPELLED_POLICY_VALUE = "internalonly"
_INPUT_REQUIRED = "at least one non-empty entry in 'sboms' or 'scanners'"
_CLI_BATCH = "cli_batch"
_INTERNAL_ONLY = "internal_only"
_NETWORK_FACING = "network_facing"


def test_request_defaults():
    req = AdhocAnalyzeRequest(sboms=[_SBOM])
    assert req.apply_global_waivers is True
    assert req.format == "json"
    assert req.analyzers is None
    assert req.callgraph is None
    assert req.license_policy is None
    assert req.scanners is None


def test_scanner_only_request_is_valid():
    req = AdhocAnalyzeRequest(scanners={"trufflehog": _TRUFFLEHOG_PAYLOAD})
    assert req.sboms == []
    assert req.scanners is not None
    assert req.scanners.trufflehog == _TRUFFLEHOG_PAYLOAD


def test_empty_request_is_rejected():
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest()
    assert _INPUT_REQUIRED in str(exc.value)


def test_a_scanners_object_carrying_no_payload_is_rejected():
    """``scanners: {}`` is not an input; without this it analyses nothing and answers 200."""
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest(scanners={})
    assert _INPUT_REQUIRED in str(exc.value)


def test_a_list_of_empty_sboms_is_rejected():
    """``sboms: [{}]`` is the empty-scanners shape one level over — still nothing to analyse."""
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest(sboms=[{}])
    assert _INPUT_REQUIRED in str(exc.value)


def test_one_real_sbom_among_empty_ones_is_accepted():
    req = AdhocAnalyzeRequest(sboms=[{}, _SBOM])
    assert req.sboms == [{}, _SBOM]


def test_unknown_request_field_is_rejected():
    """A misspelled option must not be silently dropped back to its default."""
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest(sboms=[_SBOM], aplly_global_waivers=False)
    assert [(e["type"], e["loc"]) for e in exc.value.errors()] == [(_EXTRA_FORBIDDEN, (_MISSPELLED_OPTION,))]


def test_unknown_scanner_name_is_rejected():
    """A misspelled scanner must not leave every payload empty and still validate."""
    # An SBOM comes along so the all-payloads-empty rule cannot be what rejects this.
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest(sboms=[_SBOM], scanners={_MISSPELLED_SCANNER: _TRUFFLEHOG_PAYLOAD})
    assert [(e["type"], e["loc"]) for e in exc.value.errors()] == [
        (_EXTRA_FORBIDDEN, ("scanners", _MISSPELLED_SCANNER))
    ]


def test_misspelled_license_policy_key_is_rejected():
    """Dropping the key restores the network-facing default and re-grades AGPL findings, with a 200."""
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest(sboms=[_SBOM], license_policy={_MISSPELLED_POLICY_KEY: _INTERNAL_ONLY})
    assert [(e["type"], e["loc"]) for e in exc.value.errors()] == [
        (_EXTRA_FORBIDDEN, ("license_policy", _MISSPELLED_POLICY_KEY))
    ]


def test_misspelled_license_policy_value_is_rejected():
    """An unparseable value would otherwise raise inside the analyzer instead of at the boundary."""
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest(sboms=[_SBOM], license_policy={"deployment_model": _MISSPELLED_POLICY_VALUE})
    assert [e["type"] for e in exc.value.errors()] == [_ENUM_ERROR]


def test_a_partial_license_policy_keeps_plain_string_values():
    """The license analyzer compares the policy against plain strings, not enum members."""
    req = AdhocAnalyzeRequest(sboms=[_SBOM], license_policy={"deployment_model": _CLI_BATCH})
    assert req.license_policy is not None
    assert req.license_policy.model_dump() == {
        "distribution_model": "distributed",
        "deployment_model": _CLI_BATCH,
        "library_usage": "mixed",
        "allow_strong_copyleft": False,
        "allow_network_copyleft": False,
    }


def test_the_project_policy_schema_stays_lenient():
    """Forbidding extras belongs on the ad-hoc subclass; the project API accepts unknown keys today."""
    policy = LicensePolicySchema(**{_MISSPELLED_POLICY_KEY: _INTERNAL_ONLY})
    assert policy.deployment_model == _NETWORK_FACING


def test_too_many_sboms_is_rejected():
    with pytest.raises(ValidationError):
        AdhocAnalyzeRequest(sboms=[_SBOM] * (MAX_ADHOC_SBOMS + 1))


def test_too_many_analyzers_is_rejected():
    """Every name is echoed back in the report, so an unbounded list amplifies the response."""
    with pytest.raises(ValidationError):
        AdhocAnalyzeRequest(sboms=[_SBOM], analyzers=[_ANALYZER] * (MAX_ADHOC_ANALYZERS + 1))


def test_unknown_format_is_rejected():
    with pytest.raises(ValidationError):
        AdhocAnalyzeRequest(sboms=[_SBOM], format="pdf")


def test_response_defaults_are_a_complete_envelope():
    resp = AdhocAnalyzeResponse()
    dumped = resp.model_dump()
    assert dumped["findings"] == []
    assert dumped["dependencies"] == []
    assert dumped["recommendations"] == []
    assert dumped["epss_kev_summary"] == {}
    assert dumped["reachability_summary"] is None
    assert dumped["waivers_applied"] == "none"
    assert dumped["waived_count"] == 0
    assert dumped["truncated"] is False
    assert dumped["analyzers"] == {"ran": [], "skipped": {}, "errored": {}, "skipped_inputs": {}}
    assert dumped["stats"]["threat_intel"] is None
    assert dumped["stats"]["risk_score"] == 0.0


def test_analyzer_report_carries_reasons_not_bare_names():
    report = AnalyzerReport(ran=["osv"], skipped={"grype": "CLI scanner"}, errored={"trivy": "boom"})
    assert report.skipped["grype"] == "CLI scanner"
    assert report.errored["trivy"] == "boom"


def test_unusable_inputs_are_reported_apart_from_skipped_analyzers():
    """One dict for both would force a consumer to tell analyzer names from input labels."""
    report = AnalyzerReport(skipped={_ANALYZER: "no coverage"}, skipped_inputs={_SBOM_LABEL: _SKIP_REASON})
    assert report.skipped == {_ANALYZER: "no coverage"}
    assert report.skipped_inputs == {_SBOM_LABEL: _SKIP_REASON}
