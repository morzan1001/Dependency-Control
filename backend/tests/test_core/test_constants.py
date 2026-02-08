"""Tests for constants utility functions."""

from app.core.constants import get_severity_value, sort_by_severity


class TestGetSeverityValue:
    def test_critical(self):
        assert get_severity_value("CRITICAL") == 5

    def test_high(self):
        assert get_severity_value("HIGH") == 4

    def test_medium(self):
        assert get_severity_value("MEDIUM") == 3

    def test_low(self):
        assert get_severity_value("LOW") == 2

    def test_info(self):
        assert get_severity_value("INFO") == 0

    def test_unknown(self):
        assert get_severity_value("UNKNOWN") == 0

    def test_case_insensitive(self):
        assert get_severity_value("critical") == 5
        assert get_severity_value("High") == 4

    def test_none_returns_zero(self):
        assert get_severity_value(None) == 0

    def test_empty_string_returns_zero(self):
        assert get_severity_value("") == 0

    def test_invalid_returns_zero(self):
        assert get_severity_value("INVALID") == 0


class TestSortBySeverity:
    def test_descending_by_default(self):
        items = [
            {"name": "a", "severity": "LOW"},
            {"name": "b", "severity": "CRITICAL"},
            {"name": "c", "severity": "MEDIUM"},
        ]
        result = sort_by_severity(items)
        assert result[0]["name"] == "b"
        assert result[1]["name"] == "c"
        assert result[2]["name"] == "a"

    def test_ascending(self):
        items = [
            {"severity": "CRITICAL"},
            {"severity": "LOW"},
        ]
        result = sort_by_severity(items, reverse=False)
        assert result[0]["severity"] == "LOW"
        assert result[1]["severity"] == "CRITICAL"

    def test_custom_key(self):
        items = [{"level": "LOW"}, {"level": "HIGH"}]
        result = sort_by_severity(items, key="level")
        assert result[0]["level"] == "HIGH"
        assert result[1]["level"] == "LOW"

    def test_empty_list(self):
        assert sort_by_severity([]) == []

    def test_with_objects(self):
        class Item:
            def __init__(self, severity):
                self.severity = severity

        items = [Item("LOW"), Item("CRITICAL"), Item("HIGH")]
        result = sort_by_severity(items)
        assert result[0].severity == "CRITICAL"
        assert result[1].severity == "HIGH"
        assert result[2].severity == "LOW"

    def test_stable_sort_same_severity(self):
        items = [
            {"name": "first", "severity": "HIGH"},
            {"name": "second", "severity": "HIGH"},
        ]
        result = sort_by_severity(items)
        assert result[0]["name"] == "first"
        assert result[1]["name"] == "second"
