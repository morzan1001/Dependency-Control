"""Trivy results are stored as the scanner wrote them; Grype's keep only the match keys normalize_grype reads."""

import json

import pytest

from app.services.analyzers.grype import GrypeAnalyzer
from app.services.analyzers.trivy import TrivyAnalyzer


def test_the_stored_trivy_result_is_the_parsed_scanner_output():
    raw = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "UNKNOWN"}]}]}
    assert TrivyAnalyzer()._parse_output(json.dumps(raw).encode()) == raw


@pytest.mark.parametrize("analyzer", [TrivyAnalyzer(), GrypeAnalyzer()])
def test_empty_output_is_an_empty_result(analyzer):
    assert analyzer._parse_output(b"  ") == {analyzer.empty_result_key: []}
