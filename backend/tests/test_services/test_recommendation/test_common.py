"""Tests for app.services.recommendation.common."""

from pydantic import BaseModel

from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import (
    AFFECTED_COMPONENTS_SHOWN,
    calculate_best_fix_version,
    calculate_score,
    finding_cve_ids,
    get_attr,
    name_some,
    parse_version_tuple,
    sample_components,
    sort_key,
)


def _rec(priority: Priority, rtype: RecommendationType, impact: dict) -> Recommendation:
    return Recommendation(
        type=rtype,
        priority=priority,
        title="t",
        description="d",
        impact=impact,
        affected_components=["c"],
        action={},
    )


class TestSortKey:
    def test_priority_tier_outranks_raw_volume(self):
        # a medium item with a huge vuln count must NOT outrank a critical exploit fix
        critical = _rec(Priority.CRITICAL, RecommendationType.KNOWN_EXPLOIT, {"total": 1, "critical": 1, "kev_count": 1})
        medium = _rec(Priority.MEDIUM, RecommendationType.RECURRING_VULNERABILITY, {"total": 445, "critical": 200, "high": 245})
        assert sort_key(critical) > sort_key(medium)
        assert calculate_score(medium) > calculate_score(critical), "volume alone would have ranked medium first"
        ordered = sorted([medium, critical], key=sort_key, reverse=True)
        assert ordered[0] is critical

    def test_within_tier_orders_by_score(self):
        big = _rec(Priority.HIGH, RecommendationType.DIRECT_DEPENDENCY_UPDATE, {"total": 20, "critical": 10, "high": 10})
        small = _rec(Priority.HIGH, RecommendationType.DIRECT_DEPENDENCY_UPDATE, {"total": 1, "low": 1})
        assert sort_key(big) > sort_key(small)


class _SampleModel(BaseModel):
    name: str = "default"
    version: str = "1.0.0"


class TestGetAttr:
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


def _stored_vuln(entries):
    """A vulnerability finding in the shape the aggregator persists: the document id is the
    (component, version) pair and every advisory lives in details.vulnerabilities."""
    return {
        "id": "log4j-core:2.14.1",
        "finding_id": "log4j-core:2.14.1",
        "type": "vulnerability",
        "component": "log4j-core",
        "version": "2.14.1",
        "aliases": [],
        "details": {"fixed_version": "2.15.0", "vulnerabilities": entries},
    }


class TestFindingCveIds:
    def test_reads_the_advisory_list(self):
        finding = _stored_vuln([{"id": "CVE-2021-44228"}])
        assert finding_cve_ids(finding) == ["CVE-2021-44228"]

    def test_component_version_document_id_is_never_returned(self):
        finding = _stored_vuln([{"id": "CVE-2021-44228"}])
        assert "log4j-core:2.14.1" not in finding_cve_ids(finding)

    def test_every_advisory_in_the_group_is_named(self):
        finding = _stored_vuln([{"id": "CVE-2021-44228"}, {"id": "CVE-2021-45046"}])
        assert finding_cve_ids(finding) == ["CVE-2021-44228", "CVE-2021-45046"]

    def test_ghsa_entry_collapses_to_its_cve_alias(self):
        finding = _stored_vuln([{"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]}])
        assert finding_cve_ids(finding) == ["CVE-2021-44228"]

    def test_resolved_cve_wins_over_the_entry_id(self):
        finding = _stored_vuln([{"id": "GHSA-jfh8-c2jp-5v3q", "resolved_cve": "CVE-2021-44228"}])
        assert finding_cve_ids(finding) == ["CVE-2021-44228"]

    def test_ghsa_only_advisory_keeps_its_own_id(self):
        finding = _stored_vuln([{"id": "GHSA-only-1234"}])
        assert finding_cve_ids(finding) == ["GHSA-only-1234"]

    def test_a_cve_named_by_two_entries_is_listed_once(self):
        finding = _stored_vuln([{"id": "CVE-2021-44228"}, {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]}])
        assert finding_cve_ids(finding) == ["CVE-2021-44228"]

    def test_empty_advisory_list_names_nothing(self):
        assert finding_cve_ids(_stored_vuln([])) == []

    def test_finding_without_details_names_nothing(self):
        assert finding_cve_ids({"id": "log4j-core:2.14.1"}) == []

    def test_details_not_dict_names_nothing(self):
        assert finding_cve_ids({"id": "log4j-core:2.14.1", "details": "a string"}) == []

    def test_reads_a_pydantic_finding_too(self):
        class _Finding(BaseModel):
            id: str = "log4j-core:2.14.1"
            details: dict = {"vulnerabilities": [{"id": "CVE-2021-44228"}]}

        assert finding_cve_ids(_Finding()) == ["CVE-2021-44228"]


class TestParseVersionTuple:
    def test_simple_semver(self):
        assert parse_version_tuple("1.2.3") == (1, 2, 3)

    def test_two_part_version(self):
        assert parse_version_tuple("1.2") == (1, 2)

    def test_four_part_version(self):
        assert parse_version_tuple("1.2.3.4") == (1, 2, 3, 4)

    def test_single_number(self):
        assert parse_version_tuple("42") == (42,)

    def test_prerelease_beta(self):
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
    def test_empty_list_returns_unknown(self):
        assert calculate_best_fix_version([]) == "unknown"

    def test_single_version(self):
        assert calculate_best_fix_version(["1.2.3"]) == "1.2.3"

    def test_multiple_versions_returns_highest(self):
        result = calculate_best_fix_version(["1.0.0", "2.0.0", "1.5.0"])
        assert result == "2.0.0"

    def test_comma_separated_versions(self):
        result = calculate_best_fix_version(["1.0.0, 2.0.0"])
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
        result = calculate_best_fix_version(["1.0.0, 3.0.0, 2.0.0"])
        assert result == "1.0.0, 3.0.0, 2.0.0"


def _make_recommendation(
    priority=Priority.MEDIUM,
    rec_type=RecommendationType.DIRECT_DEPENDENCY_UPDATE,
    impact=None,
    effort="medium",
) -> Recommendation:
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
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 1,
                "reachable_count": 2,
                "reachable_critical": 1,
                "reachable_high": 1,
            }
        )
        assert calculate_score(with_reach) > calculate_score(without)

    def test_unreachable_penalty_high_ratio(self):
        # >80% unreachable reduces the score significantly.
        normal = _make_recommendation(
            priority=Priority.HIGH,
            impact={"critical": 0, "high": 5, "medium": 0, "low": 0, "total": 5},
        )
        unreachable = _make_recommendation(
            priority=Priority.HIGH,
            impact={
                "critical": 0,
                "high": 5,
                "medium": 0,
                "low": 0,
                "total": 5,
                "unreachable_count": 5,
            },
        )
        assert calculate_score(unreachable) < calculate_score(normal)

    def test_unreachable_penalty_medium_ratio(self):
        # >50% but <=80% unreachable reduces the score moderately.
        normal = _make_recommendation(
            priority=Priority.HIGH,
            impact={"critical": 0, "high": 10, "medium": 0, "low": 0, "total": 10},
        )
        partial_unreach = _make_recommendation(
            priority=Priority.HIGH,
            impact={
                "critical": 0,
                "high": 10,
                "medium": 0,
                "low": 0,
                "total": 10,
                "unreachable_count": 6,
            },
        )
        assert calculate_score(partial_unreach) < calculate_score(normal)

    def test_effort_low_bonus(self):
        low_effort = _make_recommendation(effort="low")
        high_effort = _make_recommendation(effort="high")
        assert calculate_score(low_effort) > calculate_score(high_effort)

    def test_effort_medium_bonus(self):
        medium_effort = _make_recommendation(effort="medium")
        high_effort = _make_recommendation(effort="high")
        assert calculate_score(medium_effort) > calculate_score(high_effort)

    def test_type_bonus_malware_highest(self):
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

    def test_combined_threat_intel(self):
        single = _make_recommendation(
            impact={
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 1,
                "kev_count": 1,
            }
        )
        combined = _make_recommendation(
            impact={
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 1,
                "kev_count": 1,
                "high_epss_count": 1,
                "active_exploitation_count": 1,
            }
        )
        assert calculate_score(combined) > calculate_score(single)

    def test_zero_total_no_crash(self):
        # total=0 must not cause a division by zero.
        rec = _make_recommendation(
            impact={
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
                "unreachable_count": 5,
            }
        )
        score = calculate_score(rec)
        assert isinstance(score, int)


class TestSampleComponents:
    """One cut, one count: the reader always learns the size of the population."""

    def test_a_population_past_the_cap_is_counted_before_it_is_cut(self):
        covered = AFFECTED_COMPONENTS_SHOWN * 45
        shown, total = sample_components(f"pkg{index:04d}" for index in range(covered))

        assert len(shown) == AFFECTED_COMPONENTS_SHOWN
        assert total == covered

    def test_duplicates_do_not_inflate_the_population(self):
        shown, total = sample_components(["a", "b", "a", "b"])

        assert shown == ["a", "b"]
        assert total == 2

    def test_the_callers_order_survives_so_a_ranked_population_keeps_its_ranking(self):
        ranked = [f"pkg{index:04d}" for index in range(AFFECTED_COMPONENTS_SHOWN * 2)][::-1]

        shown, _total = sample_components(ranked)

        assert shown == ranked[:AFFECTED_COMPONENTS_SHOWN]

    def test_blank_entries_are_neither_listed_nor_counted(self):
        shown, total = sample_components(["a", "", "b"])

        assert shown == ["a", "b"]
        assert total == 2


class TestNameSome:
    def test_a_list_longer_than_the_prose_allows_says_how_many_it_left_out(self):
        named = 3
        values = [f"v{index}" for index in range(10)]

        assert name_some(values, named) == "v0, v1, v2 and 7 more"

    def test_a_list_the_prose_holds_whole_claims_nothing_more(self):
        assert name_some(["v0", "v1"], 3) == "v0, v1"


class TestRecommendationTotal:
    """A generator that lists everything need not repeat the number."""

    @staticmethod
    def _rec_with(components: list[str], total: int) -> Recommendation:
        return Recommendation(
            type=RecommendationType.NO_FIX_AVAILABLE,
            priority=Priority.HIGH,
            title="Vulnerability with No Fix Available",
            description="d",
            impact={},
            affected_components=components,
            action={},
            affected_components_total=total,
        )

    def test_a_complete_list_counts_itself(self):
        rec = self._rec_with(["a", "b"], 0)

        assert rec.affected_components_total == 2

    def test_a_cut_list_reports_the_population_it_was_drawn_from(self):
        covered = 900

        rec = self._rec_with(["a", "b"], covered)

        assert rec.affected_components_total == covered
        assert rec.to_dict()["affected_components_total"] == covered


class TestFindingCveIdsAdvisoryFilter:
    """A card names the advisories it is about; a seven-CVE component group is not seven KEV CVEs."""

    def _mixed(self):
        return _stored_vuln(
            [
                {"id": "CVE-2021-44228", "in_kev": True, "kev_ransomware_use": True},
                {"id": "CVE-2021-44832"},
                {"id": "CVE-2021-45046", "in_kev": True, "kev_ransomware_use": True},
                {"id": "CVE-2021-45105"},
            ]
        )

    def test_only_the_marked_advisories_are_named(self):
        marked = finding_cve_ids(self._mixed(), lambda a: bool(a.get("kev_ransomware_use")))
        assert marked == ["CVE-2021-44228", "CVE-2021-45046"]

    def test_an_unmarked_group_falls_back_to_every_cve(self):
        finding = _stored_vuln([{"id": "CVE-2021-44228"}, {"id": "CVE-2021-44832"}])
        finding["details"]["kev_ransomware_use"] = True

        marked = finding_cve_ids(finding, lambda a: bool(a.get("kev_ransomware_use")))

        assert marked == ["CVE-2021-44228", "CVE-2021-44832"]
