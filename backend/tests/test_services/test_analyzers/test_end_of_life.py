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

    def test_standard_cpe23_format_no_match(self):
        """Standard cpe:2.3:a: format (without slash) does not match the regex."""
        cpes = ["cpe:2.3:a:python:python:3.8.5:*:*:*:*:*:*:*"]
        result = self.analyzer._extract_products_from_cpes(cpes)
        assert result == set()


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
