"""Tests for sorting helper."""

from app.api.v1.helpers.sorting import parse_sort_direction, get_sort_field


class TestParseSortDirection:
    def test_desc(self):
        assert parse_sort_direction("desc") == -1

    def test_asc(self):
        assert parse_sort_direction("asc") == 1

    def test_case_insensitive_desc(self):
        assert parse_sort_direction("DESC") == -1

    def test_case_insensitive_asc(self):
        assert parse_sort_direction("ASC") == 1

    def test_unknown_defaults_to_asc(self):
        assert parse_sort_direction("random") == 1


class TestGetSortField:
    def test_valid_project_field(self):
        assert get_sort_field("projects", "name") == "name"

    def test_nested_project_field(self):
        assert get_sort_field("projects", "critical") == "stats.critical"

    def test_risk_score_maps_to_stats(self):
        assert get_sort_field("projects", "risk_score") == "stats.risk_score"

    def test_invalid_field_falls_back_to_default(self):
        assert get_sort_field("projects", "nonexistent") == "created_at"

    def test_findings_severity_maps_to_rank(self):
        assert get_sort_field("findings", "severity") == "severity_rank"

    def test_findings_component(self):
        assert get_sort_field("findings", "component") == "component"

    def test_scans_created_at(self):
        assert get_sort_field("scans", "created_at") == "created_at"

    def test_project_scans_findings_count(self):
        assert get_sort_field("project_scans", "findings_count") == "findings_count"

    def test_unknown_entity_returns_default(self):
        result = get_sort_field("unknown_entity", "name", default="created_at")
        assert result == "created_at"
