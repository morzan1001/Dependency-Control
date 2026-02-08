"""Tests for findings helper functions."""

from app.api.v1.helpers.findings import (
    get_category_type_filter,
    get_category_for_type,
    aggregate_stats_by_category,
)


class TestGetCategoryTypeFilter:
    def test_security(self):
        result = get_category_type_filter("security")
        assert result == {"$in": ["vulnerability", "malware", "typosquatting"]}

    def test_secret(self):
        assert get_category_type_filter("secret") == "secret"

    def test_sast(self):
        result = get_category_type_filter("sast")
        assert result == {"$in": ["sast", "iac"]}

    def test_compliance(self):
        result = get_category_type_filter("compliance")
        assert result == {"$in": ["license", "eol"]}

    def test_quality(self):
        result = get_category_type_filter("quality")
        assert result == {"$in": ["outdated", "quality"]}

    def test_unknown_returns_none(self):
        assert get_category_type_filter("nonexistent") is None


class TestGetCategoryForType:
    def test_vulnerability(self):
        assert get_category_for_type("vulnerability") == "security"

    def test_malware(self):
        assert get_category_for_type("malware") == "security"

    def test_typosquatting(self):
        assert get_category_for_type("typosquatting") == "security"

    def test_secret(self):
        assert get_category_for_type("secret") == "secret"

    def test_sast(self):
        assert get_category_for_type("sast") == "sast"

    def test_iac(self):
        assert get_category_for_type("iac") == "sast"

    def test_license(self):
        assert get_category_for_type("license") == "compliance"

    def test_eol(self):
        assert get_category_for_type("eol") == "compliance"

    def test_outdated(self):
        assert get_category_for_type("outdated") == "quality"

    def test_quality(self):
        assert get_category_for_type("quality") == "quality"

    def test_unknown_returns_other(self):
        assert get_category_for_type("unknown_type") == "other"


class TestAggregateStatsByCategory:
    def test_basic_aggregation(self):
        type_counts = [
            {"_id": "vulnerability", "count": 10},
            {"_id": "secret", "count": 5},
            {"_id": "sast", "count": 3},
        ]
        result = aggregate_stats_by_category(type_counts)
        assert result["security"] == 10
        assert result["secret"] == 5
        assert result["sast"] == 3
        assert result["compliance"] == 0
        assert result["quality"] == 0

    def test_multiple_types_same_category(self):
        type_counts = [
            {"_id": "vulnerability", "count": 10},
            {"_id": "malware", "count": 2},
            {"_id": "typosquatting", "count": 1},
        ]
        result = aggregate_stats_by_category(type_counts)
        assert result["security"] == 13

    def test_sast_and_iac_combined(self):
        type_counts = [
            {"_id": "sast", "count": 7},
            {"_id": "iac", "count": 3},
        ]
        result = aggregate_stats_by_category(type_counts)
        assert result["sast"] == 10

    def test_empty_list(self):
        result = aggregate_stats_by_category([])
        assert all(v == 0 for v in result.values())

    def test_unknown_types_go_to_other(self):
        type_counts = [{"_id": "custom_type", "count": 7}]
        result = aggregate_stats_by_category(type_counts)
        assert result["other"] == 7

    def test_all_categories(self):
        type_counts = [
            {"_id": "vulnerability", "count": 1},
            {"_id": "secret", "count": 2},
            {"_id": "sast", "count": 3},
            {"_id": "license", "count": 4},
            {"_id": "outdated", "count": 5},
        ]
        result = aggregate_stats_by_category(type_counts)
        assert result["security"] == 1
        assert result["secret"] == 2
        assert result["sast"] == 3
        assert result["compliance"] == 4
        assert result["quality"] == 5
