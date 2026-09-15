"""Tests for the EndOfLifeAnalyzer - end-of-life detection for components."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.finding import Severity
from app.services.analyzers.end_of_life import EndOfLifeAnalyzer


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


def _days_ahead(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")


class TestExtractProductsFromCpes:
    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    @pytest.mark.parametrize(
        "cpes",
        [
            pytest.param(["cpe:/2.3:a:python:python:3.8.5:*:*:*:*:*:*:*"], id="cpe23_with_slash"),
            pytest.param(["cpe:/a:python:python:3.8.5"], id="cpe22"),
            pytest.param(["cpe:/a:python:python:3.8.5", "cpe:/a:python:python:3.8.6"], id="two_versions_one_product"),
            # The slash after `cpe:` is optional in canonical CPE 2.3, which must still match.
            pytest.param(["cpe:2.3:a:python:python:3.8.5:*:*:*:*:*:*:*"], id="canonical_cpe23_without_slash"),
        ],
    )
    def test_python_cpes_yield_the_python_product(self, cpes):
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert len(result) >= 1
        assert "python" in result

    def test_name_to_eol_mapping_applied(self):
        cpes = ["cpe:/a:nodejs:node.js:18.0.0"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        # "node.js" should map to "nodejs" via NAME_TO_EOL_MAPPING.
        assert "nodejs" in result or "node.js" in result

    @pytest.mark.parametrize(
        "cpes",
        [
            pytest.param([], id="empty_list"),
            pytest.param(["not-a-cpe-string", "random:garbage"], id="unparseable_strings"),
        ],
    )
    def test_cpes_without_a_parseable_product_return_empty_set(self, cpes):
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert result == set()

    @pytest.mark.parametrize(
        "cpes",
        [
            # "tomcat" maps to "apache-tomcat" via NAME_TO_EOL_MAPPING.
            pytest.param(["cpe:/a:apache:tomcat:9.0.0"], id="vendor_product_combo"),
            pytest.param(["not-valid", "cpe:/a:redis:redis:6.0.0"], id="mixed_valid_and_invalid"),
        ],
    )
    def test_at_least_one_product_is_extracted(self, cpes):
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert len(result) >= 1


class TestVersionMatchesCycle:
    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    @pytest.mark.parametrize(
        ("version", "cycle", "expected"),
        [
            pytest.param("3.8", "3.8", True, id="exact_match"),
            pytest.param("3.8.5", "3.8", True, id="prefix_match"),
            pytest.param("3.8.5", "3", True, id="major_version_match"),
            pytest.param("3", "3", True, id="single_part_version_exact"),
            pytest.param("3.8.5", "2.7", False, id="different_major"),
            pytest.param("3.8.5", "3.9", False, id="different_minor"),
            # Prefix match needs a dot separator, so "3.80" must not match cycle "3.8".
            pytest.param("3.80", "3.8", False, id="prefix_substring_without_separator"),
            pytest.param("", "3.8", False, id="empty_version"),
            pytest.param("3.8.5", "", False, id="empty_cycle"),
            pytest.param("", "", False, id="both_empty"),
        ],
    )
    def test_version_matches_cycle(self, version, cycle, expected):
        assert self.analyzer._version_matches_cycle(version, cycle) is expected


class TestCreateEolIssue:
    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    @pytest.mark.parametrize(
        ("eol", "cycle", "version", "expected"),
        [
            pytest.param(True, "3.6", "3.6.15", Severity.HIGH.value, id="eol_flag_true"),
            pytest.param(_days_ago(400), "3.6", "3.6.15", Severity.HIGH.value, id="eol_over_365_days_ago"),
            pytest.param(_days_ago(250), "3.7", "3.7.0", Severity.MEDIUM.value, id="eol_over_180_days_ago"),
            pytest.param(_days_ago(30), "3.8", "3.8.0", Severity.LOW.value, id="eol_under_180_days_ago"),
            pytest.param("not-a-date", "3.6", "3.6.15", Severity.MEDIUM.value, id="invalid_date_format"),
            pytest.param(12345, "3.6", "3.6.15", Severity.MEDIUM.value, id="non_string_non_bool_eol"),
        ],
    )
    def test_severity_derived_from_eol_value(self, eol, cycle, version, expected):
        eol_info = {"eol": eol, "cycle": cycle}
        result = self.analyzer._create_eol_issue("python", version, "python", eol_info)
        assert result["severity"] == expected

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            pytest.param("component", "python", id="component"),
            pytest.param("version", "3.6.15", id="version"),
            pytest.param("product", "python", id="product"),
            pytest.param("eol_info", {"eol": True, "cycle": "3.6"}, id="eol_info"),
        ],
    )
    def test_issue_carries_input_field(self, field, expected):
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result[field] == expected

    def test_issue_contains_message(self):
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert "end-of-life" in result["message"]


class TestCheckVersion:
    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    # Cycle dicts are in endoflife.date API format.
    @pytest.mark.parametrize(
        ("version", "cycles", "expected_cycle"),
        [
            pytest.param("3.6.15", [{"cycle": "3.6", "eol": True}], "3.6", id="matching_cycle_eol_true"),
            pytest.param(
                "3.8.5",
                [{"cycle": "3.8", "eol": _days_ago(100)}, {"cycle": "3.7", "eol": True}],
                "3.8",
                id="multiple_cycles_first_match_wins",
            ),
        ],
    )
    def test_matching_eol_cycle_is_returned(self, version, cycles, expected_cycle):
        result = self.analyzer._check_version(version, cycles)
        assert result is not None
        assert result["cycle"] == expected_cycle

    @pytest.mark.parametrize(
        ("version", "cycles"),
        [
            pytest.param("3.7.5", [{"cycle": "3.7", "eol": _days_ago(100)}], id="eol_date_in_the_past"),
            pytest.param("v3.6.15", [{"cycle": "3.6", "eol": True}], id="version_with_v_prefix"),
            pytest.param(3, [{"cycle": "3", "eol": True}], id="non_string_version_converted"),
        ],
    )
    def test_end_of_life_version_is_flagged(self, version, cycles):
        result = self.analyzer._check_version(version, cycles)
        assert result is not None

    @pytest.mark.parametrize(
        ("version", "cycles"),
        [
            pytest.param("3.11.5", [{"cycle": "3.11", "eol": False}], id="matching_cycle_eol_false"),
            pytest.param("3.12.0", [{"cycle": "3.12", "eol": _days_ahead(365)}], id="eol_date_in_the_future"),
            pytest.param("3.8.5", [{"cycle": "2.7", "eol": True}], id="no_matching_cycle"),
            pytest.param("", [{"cycle": "3.6", "eol": True}], id="empty_version"),
        ],
    )
    def test_supported_version_returns_none(self, version, cycles):
        result = self.analyzer._check_version(version, cycles)
        assert result is None


class TestSeverityBoundary:
    """Severity thresholds use inclusive comparison: exactly N days past EOL sits at that tier."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()
        self.analyzer._high_after_days = 365
        self.analyzer._medium_after_days = 180

    def _issue_for_eol_days_ago(self, days_ago: int) -> str:
        eol_date = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")
        issue = self.analyzer._create_eol_issue("pkg", "1.0", "pkg", {"eol": eol_date, "cycle": "1.0"})
        return issue["severity"]

    @pytest.mark.parametrize(
        ("days_ago", "expected"),
        [
            pytest.param(365, Severity.HIGH.value, id="exactly_high_threshold"),
            pytest.param(364, Severity.MEDIUM.value, id="just_below_high"),
            pytest.param(180, Severity.MEDIUM.value, id="exactly_medium_threshold"),
            pytest.param(179, Severity.LOW.value, id="just_below_medium"),
        ],
    )
    def test_severity_at_threshold(self, days_ago, expected):
        assert self._issue_for_eol_days_ago(days_ago) == expected


class TestCollectProductsToCheck:
    """Each distinct (name, version) of a product must be kept for its own EOL check."""

    def test_distinct_versions_of_same_product_kept(self):
        from app.services.analyzers.end_of_life import collect_products_to_check

        components = [
            {"name": "python", "version": "3.8.0"},
            {"name": "python", "version": "3.11.0"},
        ]
        out = collect_products_to_check(components)
        versions = {v for _, v in out["python"]}
        assert versions == {"3.8.0", "3.11.0"}

    def test_identical_components_deduplicated(self):
        from app.services.analyzers.end_of_life import collect_products_to_check

        components = [
            {"name": "python", "version": "3.11.0"},
            {"name": "python", "version": "3.11.0"},
        ]
        out = collect_products_to_check(components)
        assert len(out["python"]) == 1

    def test_empty_components_returns_empty_dict(self):
        from app.services.analyzers.end_of_life import collect_products_to_check

        assert collect_products_to_check([]) == {}


class TestCheckVersionPreference:
    """When several cycles match a version, prefer the most-specific, then LTS within that bucket."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    def _eol_cycle(self, cycle: str, lts: bool = False) -> dict:
        # Always EOL — this exercises the selection, not the EOL detection.
        return {"cycle": cycle, "eol": "2020-01-01", "lts": lts, "latest": f"{cycle}.99"}

    def test_picks_more_specific_cycle_over_major(self):
        # 3.8.0 matches both "3" and "3.8"; most-specific wins.
        cycles = [self._eol_cycle("3"), self._eol_cycle("3.8")]
        result = self.analyzer._check_version("3.8.0", cycles)
        assert result is not None
        assert result["cycle"] == "3.8"

    @pytest.mark.parametrize(
        ("version", "cycles"),
        [
            pytest.param(
                "8.0.342",
                [
                    {"cycle": "8", "eol": "2020-01-01", "lts": False, "latest": "8.99"},
                    {"cycle": "8", "eol": "2030-01-01", "lts": True, "latest": "8.LTS"},
                ],
                id="lts_wins_the_specificity_tie_and_is_still_supported",
            ),
            pytest.param(
                "3.8.0",
                [
                    {"cycle": "3", "eol": "2015-01-01", "lts": False, "latest": "3.99"},
                    {"cycle": "3.8", "eol": "2030-01-01", "lts": True, "latest": "3.8.99"},
                ],
                id="specific_active_cycle_overrides_eol_major",
            ),
            pytest.param(
                "3.8.0",
                [
                    {"cycle": "4", "eol": "2020-01-01", "lts": False, "latest": "4.99"},
                    {"cycle": "5", "eol": "2020-01-01", "lts": False, "latest": "5.99"},
                ],
                id="no_cycle_matches",
            ),
        ],
    )
    def test_selected_cycle_yields_no_eol_verdict(self, version, cycles):
        assert self.analyzer._check_version(version, cycles) is None


class TestRecommendedUpgradeCycle:
    """The upgrade offered as the remediation for an EOL component must itself still be supported."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    def _cycles(self):
        def offset(days):
            return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")

        return [
            {"cycle": "3", "latest": "3.9.0", "eol": offset(365)},
            {"cycle": "2", "latest": "2.7.18", "eol": offset(-400)},
            {"cycle": "1", "latest": "1.5.2", "eol": offset(-2000)},
        ]

    def test_recommended_cycle_is_not_itself_end_of_life(self):
        cycles = self._cycles()
        result = self.analyzer._check_version("1.5.2", cycles)
        assert result is not None
        recommended = next(c for c in cycles if c["cycle"] == result["recommended_cycle"])
        eol_date = datetime.strptime(recommended["eol"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        assert eol_date > datetime.now(timezone.utc)
        assert result["recommended_version"] == recommended["latest"]
