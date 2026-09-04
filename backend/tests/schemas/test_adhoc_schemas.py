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

_SBOM = {"bomFormat": "CycloneDX"}
_TRUFFLEHOG_PAYLOAD = {"findings": []}
_ANALYZER = "osv"
_SBOM_LABEL = "sbom#1"
_SKIP_REASON = "could not be parsed"
_EXTRA_FORBIDDEN = "extra_forbidden"
_MISSPELLED_OPTION = "aplly_global_waivers"
_MISSPELLED_SCANNER = "trufflehogg"


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
    assert "at least one of 'sboms' or 'scanners'" in str(exc.value)


def test_a_scanners_object_carrying_no_payload_is_rejected():
    """``scanners: {}`` is not an input; without this it analyses nothing and answers 200."""
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest(scanners={})
    assert "at least one of 'sboms' or 'scanners'" in str(exc.value)


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
