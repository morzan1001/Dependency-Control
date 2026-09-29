"""Trivy and Grype results are stored as the scanner wrote them; normalize_trivy/normalize_grype build the findings."""

import json

import pytest

from app.services.analyzers.grype import GrypeAnalyzer
from app.services.analyzers.trivy import TrivyAnalyzer


@pytest.mark.parametrize("analyzer", [TrivyAnalyzer(), GrypeAnalyzer()])
def test_the_stored_result_is_the_parsed_scanner_output(analyzer):
    raw = {analyzer.empty_result_key: [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "UNKNOWN"}]}]}
    assert analyzer._parse_output(json.dumps(raw).encode()) == raw


@pytest.mark.parametrize("analyzer", [TrivyAnalyzer(), GrypeAnalyzer()])
def test_empty_output_is_an_empty_result(analyzer):
    assert analyzer._parse_output(b"  ") == {analyzer.empty_result_key: []}
