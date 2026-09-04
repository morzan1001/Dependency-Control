"""Defaults and validation rules of the ad-hoc analyze request/response models."""

import pytest
from pydantic import ValidationError

from app.schemas.adhoc import (
    MAX_ADHOC_SBOMS,
    AdhocAnalyzeRequest,
    AdhocAnalyzeResponse,
    AnalyzerReport,
)


def test_request_defaults():
    req = AdhocAnalyzeRequest(sboms=[{"bomFormat": "CycloneDX"}])
    assert req.apply_global_waivers is True
    assert req.format == "json"
    assert req.analyzers is None
    assert req.callgraph is None
    assert req.license_policy is None
    assert req.scanners is None


def test_scanner_only_request_is_valid():
    req = AdhocAnalyzeRequest(scanners={"trufflehog": {"findings": []}})
    assert req.sboms == []
    assert req.scanners is not None
    assert req.scanners.trufflehog == {"findings": []}


def test_empty_request_is_rejected():
    with pytest.raises(ValidationError) as exc:
        AdhocAnalyzeRequest()
    assert "at least one of 'sboms' or 'scanners'" in str(exc.value)


def test_too_many_sboms_is_rejected():
    with pytest.raises(ValidationError):
        AdhocAnalyzeRequest(sboms=[{"bomFormat": "CycloneDX"}] * (MAX_ADHOC_SBOMS + 1))


def test_unknown_format_is_rejected():
    with pytest.raises(ValidationError):
        AdhocAnalyzeRequest(sboms=[{}], format="pdf")


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
    assert dumped["analyzers"] == {"ran": [], "skipped": {}, "errored": {}}
    assert dumped["stats"]["threat_intel"] is None
    assert dumped["stats"]["risk_score"] == 0.0


def test_analyzer_report_carries_reasons_not_bare_names():
    report = AnalyzerReport(ran=["osv"], skipped={"grype": "CLI scanner"}, errored={"trivy": "boom"})
    assert report.skipped["grype"] == "CLI scanner"
    assert report.errored["trivy"] == "boom"
