"""Tests for app.services.recommendation.common."""

import pytest
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
    take_top,
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
    @pytest.mark.parametrize(
        ("source", "key", "expected"),
        [
            pytest.param({"key": "val"}, "key", "val", id="dict_value"),
            pytest.param({"outer": {"inner": 42}}, "outer", {"inner": 42}, id="dict_nested_value"),
            pytest.param(_SampleModel(name="test"), "name", "test", id="model_value"),
            pytest.param(_SampleModel(), "name", "default", id="model_default_field_value"),
        ],
    )
    def test_reads_the_key(self, source, key, expected):
        assert get_attr(source, key) == expected

    @pytest.mark.parametrize(
        ("source", "key"),
        [
            pytest.param({"a": 1}, "b", id="dict_missing_key"),
            pytest.param({"key": None}, "key", id="dict_key_with_none_value"),
            pytest.param(_SampleModel(), "nonexistent", id="model_missing_attr"),
            pytest.param(42, "key", id="int"),
        ],
    )
    def test_returns_none_without_a_given_default(self, source, key):
        assert get_attr(source, key) is None

    @pytest.mark.parametrize(
        ("source", "key", "default"),
        [
            pytest.param({"a": 1}, "b", "fallback", id="dict_missing_key"),
            pytest.param({}, "anything", "default", id="dict_empty"),
            pytest.param(_SampleModel(), "nonexistent", 99, id="model_missing_attr"),
            pytest.param("a string", "key", "fallback", id="string"),
            pytest.param(None, "key", "safe", id="none"),
            pytest.param([1, 2, 3], "key", "nope", id="list"),
        ],
    )
    def test_returns_the_given_default(self, source, key, default):
        assert get_attr(source, key, default) == default


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
    @pytest.mark.parametrize(
        ("entries", "expected"),
        [
            pytest.param([{"id": "CVE-2021-44228"}], ["CVE-2021-44228"], id="reads_the_advisory_list"),
            pytest.param(
                [{"id": "CVE-2021-44228"}, {"id": "CVE-2021-45046"}],
                ["CVE-2021-44228", "CVE-2021-45046"],
                id="every_advisory_in_the_group_is_named",
            ),
            pytest.param(
                [{"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]}],
                ["CVE-2021-44228"],
                id="ghsa_entry_collapses_to_its_cve_alias",
            ),
            pytest.param(
                [{"id": "GHSA-jfh8-c2jp-5v3q", "resolved_cve": "CVE-2021-44228"}],
                ["CVE-2021-44228"],
                id="resolved_cve_wins_over_the_entry_id",
            ),
            pytest.param([{"id": "GHSA-only-1234"}], ["GHSA-only-1234"], id="ghsa_only_advisory_keeps_its_own_id"),
            pytest.param(
                [{"id": "CVE-2021-44228"}, {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]}],
                ["CVE-2021-44228"],
                id="a_cve_named_by_two_entries_is_listed_once",
            ),
            pytest.param([], [], id="empty_advisory_list_names_nothing"),
        ],
    )
    def test_the_advisory_list_decides_which_cves_are_named(self, entries, expected):
        assert finding_cve_ids(_stored_vuln(entries)) == expected

    def test_component_version_document_id_is_never_returned(self):
        finding = _stored_vuln([{"id": "CVE-2021-44228"}])
        assert "log4j-core:2.14.1" not in finding_cve_ids(finding)

    @pytest.mark.parametrize(
        "finding",
        [
            pytest.param({"id": "log4j-core:2.14.1"}, id="without_details"),
            pytest.param({"id": "log4j-core:2.14.1", "details": "a string"}, id="details_not_dict"),
        ],
    )
    def test_a_finding_holding_no_advisories_names_nothing(self, finding):
        assert finding_cve_ids(finding) == []

    def test_reads_a_pydantic_finding_too(self):
        class _Finding(BaseModel):
            id: str = "log4j-core:2.14.1"
            details: dict = {"vulnerabilities": [{"id": "CVE-2021-44228"}]}

        assert finding_cve_ids(_Finding()) == ["CVE-2021-44228"]


class TestParseVersionTuple:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            pytest.param("1.2.3", (1, 2, 3), id="simple_semver"),
            pytest.param("1.2", (1, 2), id="two_part_version"),
            pytest.param("1.2.3.4", (1, 2, 3, 4), id="four_part_version"),
            pytest.param("42", (42,), id="single_number"),
            pytest.param("1.2.0-beta.1", (1, 2, 0, 1), id="prerelease_beta"),
            pytest.param("2.0.0-rc2", (2, 0, 0, 2), id="prerelease_rc"),
            pytest.param("", (), id="empty_string"),
            pytest.param("abc", (), id="no_numeric_parts"),
        ],
    )
    def test_reads_the_numeric_parts(self, version, expected):
        assert parse_version_tuple(version) == expected

    @pytest.mark.parametrize(
        ("higher", "lower"),
        [
            pytest.param("1.2.4", "1.2.3", id="patch"),
            pytest.param("2.0.0", "1.99.99", id="major"),
        ],
    )
    def test_the_tuples_compare_in_version_order(self, higher, lower):
        assert parse_version_tuple(higher) > parse_version_tuple(lower)


class TestCalculateBestFixVersion:
    @pytest.mark.parametrize(
        ("candidates", "expected"),
        [
            pytest.param([], "unknown", id="empty_list"),
            pytest.param(["1.2.3"], "1.2.3", id="single_version"),
            pytest.param(["1.0.0", "2.0.0", "1.5.0"], "2.0.0", id="multiple_versions_returns_highest"),
            pytest.param(["1.0.0, 2.0.0"], "1.0.0, 2.0.0", id="comma_separated_versions"),
            pytest.param(["", " ", "  "], "unknown", id="whitespace_only_filtered"),
            pytest.param(["", "1.0.0", " "], "1.0.0", id="mixed_whitespace_and_valid"),
            pytest.param(["  1.0.0  ", "2.0.0"], "2.0.0", id="versions_with_leading_whitespace"),
            pytest.param([None, "1.0.0"], "1.0.0", id="none_values_filtered"),
            pytest.param([None, None], "unknown", id="all_none"),
            pytest.param(["1.2.3", "1.2.4", "1.3.0"], "1.3.0", id="complex_versions"),
            pytest.param(["1.0.0, 1.5.0", "2.0.0"], "2.0.0", id="comma_separated_in_multiple_entries"),
            pytest.param(["1.0.0, 3.0.0, 2.0.0"], "1.0.0, 3.0.0, 2.0.0", id="single_comma_separated_entry_as_is"),
        ],
    )
    def test_calculate_best_fix_version(self, candidates, expected):
        assert calculate_best_fix_version(candidates) == expected


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


def _impact(**counts: int) -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, **counts}


class TestCalculateScore:
    def test_basic_medium_priority(self):
        rec = _make_recommendation(priority=Priority.MEDIUM)
        score = calculate_score(rec)
        assert isinstance(score, int)
        assert score > 0

    @pytest.mark.parametrize(
        ("higher", "lower"),
        [
            pytest.param(Priority.CRITICAL, Priority.HIGH, id="critical_over_high"),
            pytest.param(Priority.HIGH, Priority.MEDIUM, id="high_over_medium"),
            pytest.param(Priority.MEDIUM, Priority.LOW, id="medium_over_low"),
        ],
    )
    def test_a_higher_priority_scores_higher(self, higher, lower):
        assert calculate_score(_make_recommendation(priority=higher)) > calculate_score(
            _make_recommendation(priority=lower)
        )

    @pytest.mark.parametrize(
        ("stronger", "weaker"),
        [
            pytest.param(_impact(critical=3, total=3), _impact(), id="critical_findings"),
            pytest.param(_impact(high=5, total=5), _impact(), id="high_findings"),
            pytest.param(
                _impact(critical=1, total=1, kev_count=2),
                _impact(critical=1, total=1, kev_count=0),
                id="kev",
            ),
            pytest.param(
                _impact(critical=1, total=1, kev_ransomware_count=1),
                _impact(critical=1, total=1, kev_ransomware_count=0),
                id="kev_ransomware",
            ),
            pytest.param(
                _impact(high=1, total=1, high_epss_count=3),
                _impact(high=1, total=1, high_epss_count=0),
                id="high_epss",
            ),
            pytest.param(
                _impact(medium=1, total=1, medium_epss_count=2),
                _impact(medium=1, total=1, medium_epss_count=0),
                id="medium_epss",
            ),
            pytest.param(
                _impact(total=1, active_exploitation_count=1),
                _impact(total=1, active_exploitation_count=0),
                id="active_exploitation",
            ),
            pytest.param(
                _impact(total=1, reachable_count=2, reachable_critical=1, reachable_high=1),
                _impact(total=1, reachable_count=0),
                id="reachability",
            ),
            pytest.param(
                _impact(critical=1, total=1, actionable_count=3),
                _impact(critical=1, total=1, actionable_count=0),
                id="actionable",
            ),
            pytest.param(
                _impact(critical=1, total=1, kev_count=1, high_epss_count=1, active_exploitation_count=1),
                _impact(critical=1, total=1, kev_count=1),
                id="combined_threat_intel",
            ),
        ],
    )
    def test_a_stronger_impact_scores_higher(self, stronger, weaker):
        assert calculate_score(_make_recommendation(impact=stronger)) > calculate_score(
            _make_recommendation(impact=weaker)
        )

    @pytest.mark.parametrize(
        ("unreachable", "comparable"),
        [
            # >80% unreachable reduces the score significantly.
            pytest.param(_impact(high=5, total=5, unreachable_count=5), _impact(high=5, total=5), id="high_ratio"),
            # >50% but <=80% unreachable reduces the score moderately.
            pytest.param(
                _impact(high=10, total=10, unreachable_count=6),
                _impact(high=10, total=10),
                id="medium_ratio",
            ),
        ],
    )
    def test_unreachable_findings_lower_the_score(self, unreachable, comparable):
        penalised = _make_recommendation(priority=Priority.HIGH, impact=unreachable)
        normal = _make_recommendation(priority=Priority.HIGH, impact=comparable)

        assert calculate_score(penalised) < calculate_score(normal)

    def test_a_ratio_exactly_at_the_high_threshold_takes_only_the_medium_penalty(self):
        def _with_unreachable(count: int) -> Recommendation:
            return _make_recommendation(
                priority=Priority.HIGH,
                impact={
                    "critical": 0,
                    "high": 10,
                    "medium": 0,
                    "low": 0,
                    "total": 10,
                    "unreachable_count": count,
                },
            )

        at_threshold = _with_unreachable(8)
        above_threshold = _with_unreachable(9)
        mid_range = _with_unreachable(6)

        assert calculate_score(at_threshold) == calculate_score(mid_range)
        assert calculate_score(at_threshold) > calculate_score(above_threshold)

    @pytest.mark.parametrize(
        ("lighter", "heavier"),
        [
            pytest.param("low", "high", id="low_over_high"),
            pytest.param("medium", "high", id="medium_over_high"),
        ],
    )
    def test_a_lighter_effort_scores_higher(self, lighter, heavier):
        assert calculate_score(_make_recommendation(effort=lighter)) > calculate_score(
            _make_recommendation(effort=heavier)
        )

    @pytest.mark.parametrize(
        ("stronger_type", "weaker_type"),
        [
            pytest.param(
                RecommendationType.MALWARE_DETECTED,
                RecommendationType.DIRECT_DEPENDENCY_UPDATE,
                id="malware_over_direct_update",
            ),
            pytest.param(
                RecommendationType.ROTATE_SECRETS,
                RecommendationType.OUTDATED_DEPENDENCY,
                id="rotate_secrets_over_outdated",
            ),
            pytest.param(
                RecommendationType.KNOWN_EXPLOIT,
                RecommendationType.DIRECT_DEPENDENCY_UPDATE,
                id="known_exploit_over_direct_update",
            ),
        ],
    )
    def test_the_type_bonus_ranks_one_type_above_another(self, stronger_type, weaker_type):
        assert calculate_score(_make_recommendation(rec_type=stronger_type)) > calculate_score(
            _make_recommendation(rec_type=weaker_type)
        )

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

    @pytest.mark.parametrize(
        "entries",
        [
            pytest.param(["a", "b", "a", "b"], id="duplicates"),
            pytest.param(["a", "", "b"], id="blank_entries"),
        ],
    )
    def test_only_distinct_named_components_are_listed_and_counted(self, entries):
        shown, total = sample_components(entries)

        assert shown == ["a", "b"]
        assert total == 2

    def test_the_callers_order_survives_so_a_ranked_population_keeps_its_ranking(self):
        ranked = [f"pkg{index:04d}" for index in range(AFFECTED_COMPONENTS_SHOWN * 2)][::-1]

        shown, _total = sample_components(ranked)

        assert shown == ranked[:AFFECTED_COMPONENTS_SHOWN]

    def test_a_card_names_twenty_components_before_it_cuts(self):
        shown, total = sample_components(f"pkg{index:04d}" for index in range(30))

        assert len(shown) == 20
        assert total == 30


class TestTakeTop:
    """Rank and population are how a card says "you are looking at a sample"."""

    def test_a_population_that_exactly_fills_the_cap_is_not_advertised_as_a_sample(self):
        taken = take_top(["a", "b", "c"], 3)

        assert [candidate for _rank, candidate, _population in taken] == ["a", "b", "c"]
        assert {(rank, population) for rank, _candidate, population in taken} == {(0, 0)}

    def test_a_population_past_the_cap_ranks_what_it_emits_and_names_the_population(self):
        taken = take_top(["a", "b", "c", "d"], 3)

        assert taken == [(1, "a", 4), (2, "b", 4), (3, "c", 4)]


class TestNameSome:
    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            pytest.param(
                [f"v{index}" for index in range(10)],
                "v0, v1, v2 and 7 more",
                id="a_list_longer_than_the_prose_allows_says_how_many_it_left_out",
            ),
            pytest.param(["v0", "v1"], "v0, v1", id="a_list_the_prose_holds_whole_claims_nothing_more"),
        ],
    )
    def test_the_prose_names_at_most_three(self, values, expected):
        named = 3

        assert name_some(values, named) == expected


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
