"""Tests for normalizer utility functions."""

from app.models.finding import Severity
from app.services.normalizers.utils import (
    safe_severity,
    normalize_list,
    normalize_cwe_list,
    safe_get,
    build_finding_id,
    extract_cvss,
    extract_grype_cvss,
)


class TestSafeSeverity:
    def test_valid_uppercase(self):
        assert safe_severity("CRITICAL") == Severity.CRITICAL

    def test_valid_lowercase(self):
        assert safe_severity("high") == Severity.HIGH

    def test_valid_mixed_case(self):
        assert safe_severity("Medium") == Severity.MEDIUM

    def test_alias_moderate(self):
        assert safe_severity("MODERATE") == Severity.MEDIUM

    def test_alias_warning(self):
        assert safe_severity("WARNING") == Severity.MEDIUM

    def test_alias_error(self):
        assert safe_severity("ERROR") == Severity.HIGH

    def test_alias_trace(self):
        assert safe_severity("TRACE") == Severity.INFO

    def test_none_returns_default(self):
        assert safe_severity(None) == Severity.UNKNOWN

    def test_empty_string_returns_default(self):
        assert safe_severity("") == Severity.UNKNOWN

    def test_invalid_string_returns_default(self):
        assert safe_severity("BANANA") == Severity.UNKNOWN

    def test_custom_default(self):
        assert safe_severity("BANANA", default=Severity.LOW) == Severity.LOW

    def test_whitespace_trimmed(self):
        assert safe_severity("  HIGH  ") == Severity.HIGH

    def test_negligible(self):
        assert safe_severity("NEGLIGIBLE") == Severity.NEGLIGIBLE

    def test_info(self):
        assert safe_severity("info") == Severity.INFO

    def test_low(self):
        assert safe_severity("Low") == Severity.LOW


class TestNormalizeList:
    def test_string_to_list(self):
        assert normalize_list("foo") == ["foo"]

    def test_list_passthrough(self):
        assert normalize_list(["a", "b"]) == ["a", "b"]

    def test_none_returns_empty(self):
        assert normalize_list(None) == []

    def test_empty_string_returns_empty(self):
        assert normalize_list("") == []

    def test_filters_none_from_list(self):
        assert normalize_list(["a", None, "b"]) == ["a", "b"]

    def test_filters_empty_strings_from_list(self):
        assert normalize_list(["a", "", "b"]) == ["a", "b"]

    def test_empty_list(self):
        assert normalize_list([]) == []


class TestNormalizeCweList:
    def test_bare_number(self):
        assert normalize_cwe_list("327") == ["327"]

    def test_cwe_prefix(self):
        assert normalize_cwe_list("CWE-327") == ["327"]

    def test_cwe_with_description(self):
        assert normalize_cwe_list("CWE-327: Use of Broken Crypto") == ["327"]

    def test_list_of_mixed_formats(self):
        result = normalize_cwe_list(["CWE-79", "89", "CWE-22: Path Traversal"])
        assert result == ["79", "89", "22"]

    def test_none_returns_empty(self):
        assert normalize_cwe_list(None) == []

    def test_non_matching_string_returns_empty(self):
        assert normalize_cwe_list("no-numbers-here") == []

    def test_case_insensitive(self):
        assert normalize_cwe_list("cwe-100") == ["100"]

    def test_empty_string(self):
        assert normalize_cwe_list("") == []

    def test_list_with_none_values(self):
        assert normalize_cwe_list(["CWE-79", None]) == ["79"]


class TestSafeGet:
    def test_key_exists(self):
        assert safe_get({"key": "value"}, "key") == "value"

    def test_key_missing_returns_default(self):
        assert safe_get({"key": "value"}, "other") == ""

    def test_key_none_returns_default(self):
        assert safe_get({"key": None}, "key") == ""

    def test_custom_default(self):
        assert safe_get({}, "key", default="fallback") == "fallback"

    def test_key_zero_returns_zero(self):
        assert safe_get({"key": 0}, "key") == 0

    def test_key_false_returns_false(self):
        assert safe_get({"key": False}, "key") is False

    def test_key_empty_string_returns_empty(self):
        assert safe_get({"key": ""}, "key") == ""


class TestBuildFindingId:
    def test_basic_id(self):
        assert build_finding_id("CVE", "2023", "1234") == "CVE-2023-1234"

    def test_none_parts_filtered(self):
        assert build_finding_id("CVE", None, "1234") == "CVE-1234"

    def test_empty_parts_filtered(self):
        assert build_finding_id("CVE", "", "1234") == "CVE-1234"

    def test_all_empty_returns_unknown(self):
        assert build_finding_id("CVE") == "CVE-unknown"

    def test_custom_separator(self):
        assert build_finding_id("SAST", "rule1", "file.py", separator=":") == "SAST:rule1:file.py"

    def test_single_part(self):
        assert build_finding_id("MAL", "lodash") == "MAL-lodash"


class TestExtractCvss:
    def test_nvd_v3_preferred(self):
        data = {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N"}}
        score, vector = extract_cvss(data)
        assert score == 9.8
        assert vector == "CVSS:3.1/AV:N"

    def test_v2_fallback(self):
        data = {"nvd": {"V2Score": 7.5, "V2Vector": "AV:N/AC:L"}}
        score, vector = extract_cvss(data)
        assert score == 7.5
        assert vector == "AV:N/AC:L"

    def test_source_priority_nvd_over_redhat(self):
        data = {
            "nvd": {"V3Score": 9.8, "V3Vector": "NVD"},
            "redhat": {"V3Score": 7.0, "V3Vector": "RH"},
        }
        score, vector = extract_cvss(data)
        assert score == 9.8
        assert vector == "NVD"

    def test_empty_dict_returns_none(self):
        assert extract_cvss({}) == (None, None)

    def test_none_input_returns_none(self):
        assert extract_cvss(None) == (None, None)

    def test_v3_vector_returned(self):
        data = {"nvd": {"V3Score": 5.0, "V3Vector": "CVSS:3.1/AV:L"}}
        _, vector = extract_cvss(data)
        assert vector == "CVSS:3.1/AV:L"

    def test_fallback_to_lower_priority_source(self):
        data = {"ghsa": {"V3Score": 6.5, "V3Vector": "GHSA"}}
        score, _ = extract_cvss(data)
        assert score == 6.5

    def test_v2_when_v3_score_is_none(self):
        data = {"nvd": {"V3Score": None, "V2Score": 5.0, "V2Vector": "V2"}}
        score, vector = extract_cvss(data)
        assert score == 5.0
        assert vector == "V2"


class TestExtractGrypeCvss:
    def test_highest_version_selected(self):
        cvss_list = [
            {"version": "2.0", "metrics": {"baseScore": 5.0}, "vector": "V2"},
            {"version": "3.1", "metrics": {"baseScore": 9.8}, "vector": "V31"},
        ]
        score, vector = extract_grype_cvss(cvss_list)
        assert score == 9.8
        assert vector == "V31"

    def test_single_entry(self):
        cvss_list = [{"version": "3.0", "metrics": {"baseScore": 7.5}, "vector": "V3"}]
        score, vector = extract_grype_cvss(cvss_list)
        assert score == 7.5
        assert vector == "V3"

    def test_empty_list_returns_none(self):
        assert extract_grype_cvss([]) == (None, None)

    def test_none_returns_none(self):
        assert extract_grype_cvss(None) == (None, None)

    def test_no_metrics_returns_none_score(self):
        cvss_list = [{"version": "3.1", "vector": "V31"}]
        score, vector = extract_grype_cvss(cvss_list)
        assert score is None
        assert vector == "V31"

    def test_metrics_none_returns_none_score(self):
        cvss_list = [{"version": "3.1", "metrics": None, "vector": "V31"}]
        score, vector = extract_grype_cvss(cvss_list)
        assert score is None
        assert vector == "V31"

    def test_base_score_none(self):
        cvss_list = [{"version": "3.1", "metrics": {"baseScore": None}, "vector": "V31"}]
        score, _ = extract_grype_cvss(cvss_list)
        assert score is None

    def test_version_3_10_vs_3_2_picks_higher(self):
        """Version 3.10 should be picked over 3.2 (numeric comparison).
        This tests a known potential bug: string comparison would make
        '3.10' < '3.2' because '1' < '2' lexicographically.
        The correct behavior is that 3.10 > 3.2 numerically.
        """
        cvss_list = [
            {"version": "3.2", "metrics": {"baseScore": 5.0}, "vector": "V32"},
            {"version": "3.10", "metrics": {"baseScore": 9.0}, "vector": "V310"},
        ]
        score, vector = extract_grype_cvss(cvss_list)
        # Correct behavior: 3.10 > 3.2, so score should be 9.0
        # If string comparison is used, this will incorrectly return 5.0
        assert score == 9.0, (
            f"Expected score 9.0 from version 3.10, got {score}. "
            "This is a bug: string comparison of version strings treats '3.10' < '3.2'"
        )

    def test_missing_version_key_treated_as_zero(self):
        cvss_list = [
            {"metrics": {"baseScore": 3.0}, "vector": "V0"},
            {"version": "3.1", "metrics": {"baseScore": 7.0}, "vector": "V31"},
        ]
        score, vector = extract_grype_cvss(cvss_list)
        assert score == 7.0
        assert vector == "V31"
