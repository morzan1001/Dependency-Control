"""Tests for the EndOfLifeAnalyzer - end-of-life detection for components."""

from datetime import datetime, timedelta, timezone

from app.models.finding import Severity
from app.services.analyzers.end_of_life import EndOfLifeAnalyzer


class TestExtractProductsFromCpes:
    """Tests for _extract_products_from_cpes - extracts product names from CPE strings."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    def test_cpe23_format_with_slash(self):
        """CPE 2.3 format with slash prefix extracts product name."""
        cpes = ["cpe:/2.3:a:python:python:3.8.5:*:*:*:*:*:*:*"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert len(result) >= 1
        assert "python" in result

    def test_cpe22_format(self):
        """Legacy CPE 2.2 format extracts product name."""
        cpes = ["cpe:/a:python:python:3.8.5"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert len(result) >= 1
        assert "python" in result

    def test_name_to_eol_mapping_applied(self):
        """Product names are mapped via NAME_TO_EOL_MAPPING."""
        cpes = ["cpe:/a:nodejs:node.js:18.0.0"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        # "node.js" should map to "nodejs" via NAME_TO_EOL_MAPPING
        assert "nodejs" in result or "node.js" in result

    def test_multiple_cpes_produce_unique_products(self):
        cpes = [
            "cpe:/a:python:python:3.8.5",
            "cpe:/a:python:python:3.8.6",
        ]
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert "python" in result

    def test_empty_list_returns_empty_set(self):
        result = self.analyzer._extract_products_from_cpes([])
        assert result == set()

    def test_invalid_cpe_string_ignored(self):
        """Strings that don't match CPE patterns are ignored."""
        cpes = ["not-a-cpe-string", "random:garbage"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert result == set()

    def test_vendor_product_combo_mapping(self):
        """Vendor_product combo lookup in NAME_TO_EOL_MAPPING."""
        cpes = ["cpe:/a:apache:tomcat:9.0.0"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        # "tomcat" maps to "apache-tomcat" via NAME_TO_EOL_MAPPING
        assert len(result) >= 1

    def test_mixed_valid_and_invalid_cpes(self):
        cpes = [
            "not-valid",
            "cpe:/a:redis:redis:6.0.0",
        ]
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert len(result) >= 1

    def test_standard_cpe23_format_matches(self):
        """Standard cpe:2.3:a:vendor:product:... is the canonical NIST format
        and the most common form in real SBOMs. Earlier versions of the
        regex required an extra `:` or `/` after `cpe:`, silently missing
        every standard CPE 2.3 entry; the fix lets the slash be optional."""
        cpes = ["cpe:2.3:a:python:python:3.8.5:*:*:*:*:*:*:*"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert "python" in result


class TestVersionMatchesCycle:
    """Tests for _version_matches_cycle - checks if a version belongs to an EOL cycle."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    def test_exact_match(self):
        assert self.analyzer._version_matches_cycle("3.8", "3.8") is True

    def test_prefix_match(self):
        """'3.8.5' matches cycle '3.8'."""
        assert self.analyzer._version_matches_cycle("3.8.5", "3.8") is True

    def test_major_version_match(self):
        """'3.8.5' matches cycle '3' via major version."""
        assert self.analyzer._version_matches_cycle("3.8.5", "3") is True

    def test_major_minor_match(self):
        """'3.8.5' matches cycle '3.8' via major.minor."""
        assert self.analyzer._version_matches_cycle("3.8.5", "3.8") is True

    def test_no_match_different_major(self):
        assert self.analyzer._version_matches_cycle("3.8.5", "2.7") is False

    def test_no_match_different_minor(self):
        assert self.analyzer._version_matches_cycle("3.8.5", "3.9") is False

    def test_empty_version_returns_false(self):
        assert self.analyzer._version_matches_cycle("", "3.8") is False

    def test_empty_cycle_returns_false(self):
        assert self.analyzer._version_matches_cycle("3.8.5", "") is False

    def test_both_empty_returns_false(self):
        assert self.analyzer._version_matches_cycle("", "") is False

    def test_single_part_version_exact(self):
        """Version '3' matches cycle '3'."""
        assert self.analyzer._version_matches_cycle("3", "3") is True

    def test_version_does_not_match_prefix_substring(self):
        """'3.80' should not match cycle '3.8' via prefix (needs dot separator)."""
        assert self.analyzer._version_matches_cycle("3.80", "3.8") is False


class TestCreateEolIssue:
    """Tests for _create_eol_issue - creates issue dicts with severity based on EOL date."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    def test_eol_true_returns_high(self):
        """eol=True (boolean) produces HIGH severity."""
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["severity"] == Severity.HIGH.value

    def test_eol_date_over_365_days_ago_returns_high(self):
        """EOL date more than 365 days ago produces HIGH severity."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%d")
        eol_info = {"eol": past_date, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["severity"] == Severity.HIGH.value

    def test_eol_date_over_180_days_ago_returns_medium(self):
        """EOL date between 180-365 days ago produces MEDIUM severity."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=250)).strftime("%Y-%m-%d")
        eol_info = {"eol": past_date, "cycle": "3.7"}
        result = self.analyzer._create_eol_issue("python", "3.7.0", "python", eol_info)
        assert result["severity"] == Severity.MEDIUM.value

    def test_eol_date_under_180_days_ago_returns_low(self):
        """EOL date less than 180 days ago produces LOW severity."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        eol_info = {"eol": past_date, "cycle": "3.8"}
        result = self.analyzer._create_eol_issue("python", "3.8.0", "python", eol_info)
        assert result["severity"] == Severity.LOW.value

    def test_invalid_date_format_returns_medium(self):
        """Unparseable date string produces MEDIUM severity."""
        eol_info = {"eol": "not-a-date", "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["severity"] == Severity.MEDIUM.value

    def test_non_string_non_bool_eol_returns_medium(self):
        """Non-string, non-bool eol value produces MEDIUM severity."""
        eol_info = {"eol": 12345, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["severity"] == Severity.MEDIUM.value

    def test_issue_contains_component(self):
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["component"] == "python"

    def test_issue_contains_version(self):
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["version"] == "3.6.15"

    def test_issue_contains_product(self):
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["product"] == "python"

    def test_issue_contains_message(self):
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert "end-of-life" in result["message"]

    def test_issue_contains_eol_info(self):
        eol_info = {"eol": True, "cycle": "3.6"}
        result = self.analyzer._create_eol_issue("python", "3.6.15", "python", eol_info)
        assert result["eol_info"] == eol_info


class TestCheckVersion:
    """Tests for _check_version - checks if a version matches an EOL cycle."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    def _make_cycle(self, cycle, eol):
        """Create a cycle dict matching endoflife.date API format."""
        return {"cycle": cycle, "eol": eol}

    def test_matching_cycle_eol_true(self):
        """Version matching a cycle with eol=True returns the cycle."""
        cycles = [self._make_cycle("3.6", True)]
        result = self.analyzer._check_version("3.6.15", cycles)
        assert result is not None
        assert result["cycle"] == "3.6"

    def test_matching_cycle_eol_date_past(self):
        """Version matching a cycle with past EOL date returns the cycle."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
        cycles = [self._make_cycle("3.7", past_date)]
        result = self.analyzer._check_version("3.7.5", cycles)
        assert result is not None

    def test_matching_cycle_eol_false(self):
        """Version matching a cycle with eol=False returns None (not EOL)."""
        cycles = [self._make_cycle("3.11", False)]
        result = self.analyzer._check_version("3.11.5", cycles)
        assert result is None

    def test_matching_cycle_eol_future_date(self):
        """Version matching a cycle with future EOL date returns None."""
        future_date = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%d")
        cycles = [self._make_cycle("3.12", future_date)]
        result = self.analyzer._check_version("3.12.0", cycles)
        assert result is None

    def test_no_matching_cycle(self):
        """Version not matching any cycle returns None."""
        cycles = [self._make_cycle("2.7", True)]
        result = self.analyzer._check_version("3.8.5", cycles)
        assert result is None

    def test_empty_version_returns_none(self):
        cycles = [self._make_cycle("3.6", True)]
        result = self.analyzer._check_version("", cycles)
        assert result is None

    def test_version_with_v_prefix(self):
        """Version strings with 'v' prefix are cleaned."""
        cycles = [self._make_cycle("3.6", True)]
        result = self.analyzer._check_version("v3.6.15", cycles)
        assert result is not None

    def test_multiple_cycles_first_match_wins(self):
        """First matching cycle in the list is returned."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%d")
        cycles = [
            self._make_cycle("3.8", past_date),
            self._make_cycle("3.7", True),
        ]
        result = self.analyzer._check_version("3.8.5", cycles)
        assert result is not None
        assert result["cycle"] == "3.8"

    def test_non_string_version_converted(self):
        """Non-string version is converted to string."""
        cycles = [self._make_cycle("3", True)]
        result = self.analyzer._check_version(3, cycles)
        assert result is not None


class TestSeverityBoundary:
    """Audit P6.2: the severity escalation thresholds were strictly-greater-
    than. A package exactly N days past EOL fell one tier below where it
    belonged. We use inclusive comparison so the threshold names match the
    behaviour ("HIGH after 365 days" really means at 365 days)."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()
        # Skip __init__-time settings; just call _create_eol_issue directly.
        self.analyzer._high_after_days = 365
        self.analyzer._medium_after_days = 180

    def _issue_for_eol_days_ago(self, days_ago: int) -> str:
        eol_date = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")
        issue = self.analyzer._create_eol_issue(
            "pkg", "1.0", "pkg", {"eol": eol_date, "cycle": "1.0"}
        )
        return issue["severity"]

    def test_exactly_high_threshold_returns_high(self):
        # 365 days past EOL is at the HIGH threshold — must be HIGH, not MEDIUM.
        assert self._issue_for_eol_days_ago(365) == Severity.HIGH.value

    def test_exactly_medium_threshold_returns_medium(self):
        assert self._issue_for_eol_days_ago(180) == Severity.MEDIUM.value

    def test_just_below_medium_returns_low(self):
        assert self._issue_for_eol_days_ago(179) == Severity.LOW.value

    def test_just_below_high_returns_medium(self):
        assert self._issue_for_eol_days_ago(364) == Severity.MEDIUM.value


class TestCollectProductsToCheck:
    """Audit P6.2: the analyzer used to keep only the *first* (name, version)
    pair per product, silently dropping every later occurrence — so the same
    runtime present at two versions in the SBOM had only one EOL check."""

    def test_distinct_versions_of_same_product_kept(self):
        from app.services.analyzers.end_of_life import collect_products_to_check

        components = [
            {"name": "python", "version": "3.8.0"},
            {"name": "python", "version": "3.11.0"},
        ]
        out = collect_products_to_check(components)
        # Both versions must appear so each gets independently checked
        # against the cycles returned for "python".
        versions = {v for _, v in out["python"]}
        assert versions == {"3.8.0", "3.11.0"}

    def test_identical_components_deduplicated(self):
        from app.services.analyzers.end_of_life import collect_products_to_check

        # The same (name, version) repeated should not produce duplicate work.
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
    """Audit P7.1: when more than one cycle matches a version, the analyzer
    used to return whichever appeared first in endoflife.date's response.
    That gave inconsistent answers depending on API order. We now prefer
    the most-specific matching cycle, then prefer LTS within that bucket."""

    def setup_method(self):
        self.analyzer = EndOfLifeAnalyzer()

    def _eol_cycle(self, cycle: str, lts: bool = False) -> dict:
        # Always EOL — we test the *selection*, not the EOL detection itself.
        return {"cycle": cycle, "eol": "2020-01-01", "lts": lts, "latest": f"{cycle}.99"}

    def test_picks_more_specific_cycle_over_major(self):
        # 3.8.0 matches both "3" and "3.8". Most-specific wins.
        cycles = [self._eol_cycle("3"), self._eol_cycle("3.8")]
        result = self.analyzer._check_version("3.8.0", cycles)
        assert result is not None
        assert result["cycle"] == "3.8"

    def test_picks_lts_when_specificity_ties(self):
        # If two equally-specific cycles match (rare in practice — Java's
        # `8` and `8-LTS` for example), prefer the LTS one.
        cycles = [
            {"cycle": "8", "eol": "2020-01-01", "lts": False, "latest": "8.99"},
            {"cycle": "8", "eol": "2030-01-01", "lts": True, "latest": "8.LTS"},
        ]
        result = self.analyzer._check_version("8.0.342", cycles)
        # The LTS one isn't EOL (2030 in future) so this should return None,
        # not the non-LTS EOL one — LTS preference must win selection.
        assert result is None

    def test_more_specific_non_eol_overrides_less_specific_eol(self):
        # 3.8.0 matches both "3" (EOL) and "3.8" (active). The specific
        # cycle is the truth — the version is NOT EOL.
        cycles = [
            {"cycle": "3", "eol": "2015-01-01", "lts": False, "latest": "3.99"},
            {"cycle": "3.8", "eol": "2030-01-01", "lts": True, "latest": "3.8.99"},
        ]
        result = self.analyzer._check_version("3.8.0", cycles)
        assert result is None

    def test_returns_none_when_no_cycle_matches(self):
        cycles = [self._eol_cycle("4"), self._eol_cycle("5")]
        assert self.analyzer._check_version("3.8.0", cycles) is None
