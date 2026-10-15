from app.api.v1.helpers.sorting import case_insensitive_key, get_sort_field, parse_sort_direction


class TestCaseInsensitiveKey:
    def test_accented_names_sort_beside_their_base_letters_as_the_collation_sorts_them(self):
        names = ["Zahlung", "strat", "éclair", "Straße", "Ärzte", "navy", "Bravo", "naïve", "ezra", "cello", "eclair"]

        assert sorted(names, key=case_insensitive_key) == [
            "Ärzte",
            "Bravo",
            "cello",
            "eclair",
            "éclair",
            "ezra",
            "naïve",
            "navy",
            "Straße",
            "strat",
            "Zahlung",
        ]


class TestParseSortDirection:
    def test_desc(self):
        assert parse_sort_direction("desc") == -1

    def test_asc(self):
        assert parse_sort_direction("asc") == 1


class TestGetSortField:
    def test_valid_project_field(self):
        assert get_sort_field("projects", "name") == "name"

    def test_nested_project_field(self):
        assert get_sort_field("projects", "critical") == "stats.critical"

    def test_risk_score_maps_to_stats(self):
        assert get_sort_field("projects", "risk_score") == "stats.risk_score"

    def test_invalid_field_falls_back_to_default(self):
        assert get_sort_field("projects", "nonexistent") == "created_at"

    def test_scans_created_at(self):
        assert get_sort_field("scans", "created_at") == "created_at"

    def test_project_scans_findings_count(self):
        assert get_sort_field("project_scans", "findings_count") == "findings_count"

    def test_unknown_entity_returns_default(self):
        result = get_sort_field("unknown_entity", "name", default="created_at")
        assert result == "created_at"
