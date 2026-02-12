"""Tests for app.services.recommendation.common."""

from pydantic import BaseModel

from app.services.recommendation.common import (
    get_attr,
    extract_cve_id,
    parse_version_tuple,
    calculate_best_fix_version,
    calculate_score,
)
from app.schemas.recommendation import (
    Recommendation,
    RecommendationType,
    Priority,
)


class _SampleModel(BaseModel):
    name: str = "default"
    version: str = "1.0.0"


class TestGetAttr:
    """Tests for get_attr - unified accessor for Pydantic models and dicts."""

    def test_dict_returns_value(self):
        assert get_attr({"key": "val"}, "key") == "val"

    def test_dict_missing_key_returns_default(self):
        assert get_attr({"a": 1}, "b") is None

    def test_dict_missing_key_returns_custom_default(self):
        assert get_attr({"a": 1}, "b", "fallback") == "fallback"

    def test_dict_key_with_none_value(self):
        assert get_attr({"key": None}, "key") is None

    def test_dict_nested_value(self):
        d = {"outer": {"inner": 42}}
        assert get_attr(d, "outer") == {"inner": 42}

    def test_dict_empty(self):
        assert get_attr({}, "anything", "default") == "default"

    def test_model_returns_value(self):
        m = _SampleModel(name="test")
        assert get_attr(m, "name") == "test"

    def test_model_missing_attr_returns_default(self):
        m = _SampleModel()
        assert get_attr(m, "nonexistent") is None

    def test_model_missing_attr_returns_custom_default(self):
        m = _SampleModel()
        assert get_attr(m, "nonexistent", 99) == 99

    def test_model_default_field_value(self):
        m = _SampleModel()
        assert get_attr(m, "name") == "default"

    def test_string_returns_default(self):
        assert get_attr("a string", "key", "fallback") == "fallback"

    def test_int_returns_default(self):
        assert get_attr(42, "key") is None

    def test_none_returns_default(self):
        assert get_attr(None, "key", "safe") == "safe"

    def test_list_returns_default(self):
        assert get_attr([1, 2, 3], "key", "nope") == "nope"


class TestExtractCveId:
    """Tests for extract_cve_id - extracts CVE ID from finding via multiple strategies."""

    def test_direct_id_field(self):
        finding = {"id": "CVE-2024-0001"}
        assert extract_cve_id(finding) == "CVE-2024-0001"

    def test_direct_finding_id_field(self):
        finding = {"finding_id": "CVE-2024-9999"}
        assert extract_cve_id(finding) == "CVE-2024-9999"

    def test_direct_id_non_cve_skipped(self):
        """Non-CVE IDs in the id field should fall through to other strategies."""
        finding = {"id": "GHSA-1234-abcd-5678"}
        assert extract_cve_id(finding) is None

    def test_details_cve_id(self):
        finding = {"id": "some-id", "details": {"cve_id": "CVE-2023-5555"}}
        assert extract_cve_id(finding) == "CVE-2023-5555"

    def test_details_cve_id_non_cve_ignored(self):
        finding = {"id": "nope", "details": {"cve_id": "GHSA-xyz"}}
        assert extract_cve_id(finding) is None

    def test_details_cve_id_none_value(self):
        finding = {"id": "nope", "details": {"cve_id": None}}
        assert extract_cve_id(finding) is None

    def test_alias_cve(self):
        finding = {"id": "GHSA-abc", "aliases": ["CVE-2022-1111", "GHSA-def"]}
        assert extract_cve_id(finding) == "CVE-2022-1111"

    def test_alias_first_cve_taken(self):
        finding = {"id": "nope", "aliases": ["GHSA-1", "CVE-2022-2222", "CVE-2022-3333"]}
        assert extract_cve_id(finding) == "CVE-2022-2222"

    def test_aliases_in_details(self):
        finding = {"id": "nope", "details": {"aliases": ["CVE-2021-7777"]}}
        assert extract_cve_id(finding) == "CVE-2021-7777"

    def test_aliases_empty_list(self):
        finding = {"id": "nope", "aliases": []}
        assert extract_cve_id(finding) is None

    def test_aliases_no_cve_in_list(self):
        finding = {"id": "nope", "aliases": ["GHSA-1", "GHSA-2"]}
        assert extract_cve_id(finding) is None

    def test_no_cve_at_all(self):
        finding = {"id": "SOMETHING", "details": {}, "aliases": []}
        assert extract_cve_id(finding) is None

    def test_empty_finding(self):
        assert extract_cve_id({}) is None

    def test_finding_without_aliases_or_details(self):
        finding = {"id": "nope"}
        assert extract_cve_id(finding) is None

    def test_none_aliases_handled(self):
        """aliases field is None instead of a list."""
        finding = {"id": "nope", "aliases": None}
        assert extract_cve_id(finding) is None

    def test_details_not_dict_ignored(self):
        """If details is not a dict, strategies 2 and 3 should not crash."""
        finding = {"id": "nope", "details": "a string"}
        assert extract_cve_id(finding) is None


class TestParseVersionTuple:
    """Tests for parse_version_tuple - parses version string into comparable tuple."""

    def test_simple_semver(self):
        assert parse_version_tuple("1.2.3") == (1, 2, 3)

    def test_two_part_version(self):
        assert parse_version_tuple("1.2") == (1, 2)

    def test_four_part_version(self):
        assert parse_version_tuple("1.2.3.4") == (1, 2, 3, 4)

    def test_single_number(self):
        assert parse_version_tuple("42") == (42,)

    def test_prerelease_beta(self):
        """'1.2.0-beta.1' should parse numeric parts: (1, 2, 0, 1)."""
        assert parse_version_tuple("1.2.0-beta.1") == (1, 2, 0, 1)

    def test_prerelease_rc(self):
        assert parse_version_tuple("2.0.0-rc2") == (2, 0, 0, 2)

    def test_version_comparison_higher_wins(self):
        assert parse_version_tuple("1.2.4") > parse_version_tuple("1.2.3")

    def test_version_comparison_major(self):
        assert parse_version_tuple("2.0.0") > parse_version_tuple("1.99.99")

    def test_empty_string(self):
        assert parse_version_tuple("") == ()

    def test_no_numeric_parts(self):
        assert parse_version_tuple("abc") == ()


class TestCalculateBestFixVersion:
    """Tests for calculate_best_fix_version - picks highest version from a list."""

    def test_empty_list_returns_unknown(self):
        assert calculate_best_fix_version([]) == "unknown"

    def test_single_version(self):
        assert calculate_best_fix_version(["1.2.3"]) == "1.2.3"

    def test_multiple_versions_returns_highest(self):
        result = calculate_best_fix_version(["1.0.0", "2.0.0", "1.5.0"])
        assert result == "2.0.0"

    def test_comma_separated_versions(self):
        """A single string with comma-separated versions is returned as-is (not split)."""
        result = calculate_best_fix_version(["1.0.0, 2.0.0"])
        # Current implementation does not split comma-separated strings
        assert result == "1.0.0, 2.0.0"

    def test_whitespace_only_filtered(self):
        assert calculate_best_fix_version(["", " ", "  "]) == "unknown"

    def test_mixed_whitespace_and_valid(self):
        result = calculate_best_fix_version(["", "1.0.0", " "])
        assert result == "1.0.0"

    def test_versions_with_leading_whitespace(self):
        result = calculate_best_fix_version(["  1.0.0  ", "2.0.0"])
        assert result == "2.0.0"

    def test_none_values_filtered(self):
        """None values should be skipped (they are falsy)."""
        result = calculate_best_fix_version([None, "1.0.0"])
        assert result == "1.0.0"

    def test_all_none_returns_unknown(self):
        assert calculate_best_fix_version([None, None]) == "unknown"

    def test_complex_versions(self):
        result = calculate_best_fix_version(["1.2.3", "1.2.4", "1.3.0"])
        assert result == "1.3.0"

    def test_comma_separated_in_multiple_entries(self):
        result = calculate_best_fix_version(["1.0.0, 1.5.0", "2.0.0"])
        assert result == "2.0.0"

    def test_single_comma_separated_entry_returned_as_is(self):
        """Comma-separated versions in a single string are not parsed individually."""
        result = calculate_best_fix_version(["1.0.0, 3.0.0, 2.0.0"])
        assert result == "1.0.0, 3.0.0, 2.0.0"


def _make_recommendation(
    priority=Priority.MEDIUM,
    rec_type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
    impact=None,
    effort="medium",
) -> Recommendation:
    """Helper factory for creating minimal Recommendation objects."""
    return Recommendation(
        type=rec_type,
        priority=priority,
        title="Test Recommendation",
        description="A test recommendation.",
        impact=impact or {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        affected_components=["test-pkg"],
        action={"type": "test"},
        effort=effort,
    )


class TestCalculateScore:
    """Tests for calculate_score - produces numeric score for recommendation sorting."""

    def test_basic_medium_priority(self):
        rec = _make_recommendation(priority=Priority.MEDIUM)
        score = calculate_score(rec)
        assert isinstance(score, int)
        assert score > 0

    def test_critical_higher_than_high(self):
        critical = _make_recommendation(priority=Priority.CRITICAL)
        high = _make_recommendation(priority=Priority.HIGH)
        assert calculate_score(critical) > calculate_score(high)

    def test_high_higher_than_medium(self):
        high = _make_recommendation(priority=Priority.HIGH)
        medium = _make_recommendation(priority=Priority.MEDIUM)
        assert calculate_score(high) > calculate_score(medium)

    def test_medium_higher_than_low(self):
        medium = _make_recommendation(priority=Priority.MEDIUM)
        low = _make_recommendation(priority=Priority.LOW)
        assert calculate_score(medium) > calculate_score(low)

    def test_impact_critical_adds_score(self):
        no_impact = _make_recommendation(impact={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        with_impact = _make_recommendation(impact={"critical": 3, "high": 0, "medium": 0, "low": 0, "total": 3})
        assert calculate_score(with_impact) > calculate_score(no_impact)

    def test_impact_high_adds_score(self):
        no_impact = _make_recommendation(impact={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        with_impact = _make_recommendation(impact={"critical": 0, "high": 5, "medium": 0, "low": 0, "total": 5})
        assert calculate_score(with_impact) > calculate_score(no_impact)

    def test_kev_bonus(self):
        """KEV count in impact should boost the score."""
        without_kev = _make_recommendation(
            impact={"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "kev_count": 0}
        )
        with_kev = _make_recommendation(
            impact={"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "kev_count": 2}
        )
        assert calculate_score(with_kev) > calculate_score(without_kev)

    def test_kev_ransomware_bonus(self):
        without = _make_recommendation(
            impact={"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "kev_ransomware_count": 0}
        )
        with_rw = _make_recommendation(
            impact={"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "kev_ransomware_count": 1}
        )
        assert calculate_score(with_rw) > calculate_score(without)

    def test_high_epss_bonus(self):
        without = _make_recommendation(
            impact={"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1, "high_epss_count": 0}
        )
        with_epss = _make_recommendation(
            impact={"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1, "high_epss_count": 3}
        )
        assert calculate_score(with_epss) > calculate_score(without)

    def test_medium_epss_bonus(self):
        without = _make_recommendation(
            impact={"critical": 0, "high": 0, "medium": 1, "low": 0, "total": 1, "medium_epss_count": 0}
        )
        with_epss = _make_recommendation(
            impact={"critical": 0, "high": 0, "medium": 1, "low": 0, "total": 1, "medium_epss_count": 2}
        )
        assert calculate_score(with_epss) > calculate_score(without)

    def test_active_exploitation_bonus(self):
        without = _make_recommendation(
            impact={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 1, "active_exploitation_count": 0}
        )
        with_exploit = _make_recommendation(
            impact={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 1, "active_exploitation_count": 1}
        )
        assert calculate_score(with_exploit) > calculate_score(without)

    def test_reachability_boosts_score(self):
        without = _make_recommendation(
            impact={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 1, "reachable_count": 0}
        )
        with_reach = _make_recommendation(
            impact={
                "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 1,
                "reachable_count": 2, "reachable_critical": 1, "reachable_high": 1,
            }
        )
        assert calculate_score(with_reach) > calculate_score(without)

    def test_unreachable_penalty_high_ratio(self):
        """When >80% unreachable, score should be reduced significantly."""
        normal = _make_recommendation(
            priority=Priority.HIGH,
            impact={"critical": 0, "high": 5, "medium": 0, "low": 0, "total": 5},
        )
        unreachable = _make_recommendation(
            priority=Priority.HIGH,
            impact={
                "critical": 0, "high": 5, "medium": 0, "low": 0, "total": 5,
                "unreachable_count": 5,
            },
        )
        assert calculate_score(unreachable) < calculate_score(normal)

    def test_unreachable_penalty_medium_ratio(self):
        """When >50% but <=80% unreachable, score should be moderately reduced."""
        normal = _make_recommendation(
            priority=Priority.HIGH,
            impact={"critical": 0, "high": 10, "medium": 0, "low": 0, "total": 10},
        )
        partial_unreach = _make_recommendation(
            priority=Priority.HIGH,
            impact={
                "critical": 0, "high": 10, "medium": 0, "low": 0, "total": 10,
                "unreachable_count": 6,
            },
        )
        assert calculate_score(partial_unreach) < calculate_score(normal)

    def test_effort_low_bonus(self):
        """Low effort should score higher than high effort."""
        low_effort = _make_recommendation(effort="low")
        high_effort = _make_recommendation(effort="high")
        assert calculate_score(low_effort) > calculate_score(high_effort)

    def test_effort_medium_bonus(self):
        medium_effort = _make_recommendation(effort="medium")
        high_effort = _make_recommendation(effort="high")
        assert calculate_score(medium_effort) > calculate_score(high_effort)

    def test_type_bonus_malware_highest(self):
        """Malware detected type should have highest type bonus."""
        malware = _make_recommendation(rec_type=RecommendationType.MALWARE_DETECTED)
        direct = _make_recommendation(rec_type=RecommendationType.DIRECT_DEPENDENCY_UPDATE)
        assert calculate_score(malware) > calculate_score(direct)

    def test_type_bonus_rotate_secrets(self):
        secrets = _make_recommendation(rec_type=RecommendationType.ROTATE_SECRETS)
        outdated = _make_recommendation(rec_type=RecommendationType.OUTDATED_DEPENDENCY)
        assert calculate_score(secrets) > calculate_score(outdated)

    def test_type_bonus_known_exploit(self):
        exploit = _make_recommendation(rec_type=RecommendationType.KNOWN_EXPLOIT)
        direct = _make_recommendation(rec_type=RecommendationType.DIRECT_DEPENDENCY_UPDATE)
        assert calculate_score(exploit) > calculate_score(direct)

    def test_actionable_bonus(self):
        without = _make_recommendation(
            impact={"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "actionable_count": 0}
        )
        with_actionable = _make_recommendation(
            impact={"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "actionable_count": 3}
        )
        assert calculate_score(with_actionable) > calculate_score(without)

    def test_score_is_integer(self):
        rec = _make_recommendation()
        assert isinstance(calculate_score(rec), int)

    def test_combined_threat_intel(self):
        """Multiple threat intel signals should stack."""
        single = _make_recommendation(
            impact={
                "critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1,
                "kev_count": 1,
            }
        )
        combined = _make_recommendation(
            impact={
                "critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1,
                "kev_count": 1, "high_epss_count": 1, "active_exploitation_count": 1,
            }
        )
        assert calculate_score(combined) > calculate_score(single)

    def test_zero_total_no_crash(self):
        """If total is 0 in impact, should not divide by zero."""
        rec = _make_recommendation(
            impact={
                "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0,
                "unreachable_count": 5,
            }
        )
        # total defaults to 1 in the code, so this should not crash
        score = calculate_score(rec)
        assert isinstance(score, int)
