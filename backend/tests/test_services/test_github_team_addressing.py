"""How a bound GitHub team is addressed, and what the binding UI is offered to choose from."""

import pytest

from app.services.github import build_org_team_options, build_team_slug_map


class TestSlugMap:
    def test_maps_the_team_number_onto_the_slug_the_organisation_reports(self):
        org_teams = [{"id": 1, "slug": "platform"}, {"id": 2, "slug": "payments"}]
        assert build_team_slug_map(org_teams) == {1: "platform", 2: "payments"}

    @pytest.mark.parametrize(
        "malformed",
        [
            pytest.param({"slug": "nameless"}, id="id-missing"),
            pytest.param({"id": None, "slug": "nulled"}, id="id-null"),
            pytest.param({"id": "MDQ6VGVhbTE=", "slug": "opaque"}, id="id-not-a-number"),
            pytest.param({"id": 9}, id="slug-missing"),
            pytest.param({"id": 9, "slug": None}, id="slug-null"),
            pytest.param({"id": 9, "slug": ""}, id="slug-empty"),
        ],
    )
    def test_an_entry_that_cannot_address_a_team_is_left_out(self, malformed):
        assert build_team_slug_map([malformed, {"id": 3, "slug": "sound"}]) == {3: "sound"}


class TestOrgTeamOptions:
    """What the binding UI is offered to choose from."""

    def test_the_parent_tells_two_teams_of_the_same_name_apart(self):
        org_teams = [
            {"id": 1, "slug": "cards", "name": "Cards", "parent": {"id": 9, "slug": "payments", "name": "Payments"}},
            {"id": 2, "slug": "cards-eng", "name": "Cards", "parent": None},
        ]
        assert build_org_team_options(org_teams) == [
            {"id": 1, "slug": "cards", "name": "Cards", "parent_slug": "payments", "parent_name": "Payments"},
            {"id": 2, "slug": "cards-eng", "name": "Cards", "parent_slug": None, "parent_name": None},
        ]

    def test_a_nameless_team_is_offered_under_its_slug(self):
        options = build_org_team_options([{"id": 1, "slug": "payments", "parent": None}])
        assert options[0]["name"] == "payments"

    @pytest.mark.parametrize(
        "malformed",
        [
            pytest.param({"slug": "nameless"}, id="id-missing"),
            pytest.param({"id": None, "slug": "nulled"}, id="id-null"),
            pytest.param({"id": 9}, id="slug-missing"),
            pytest.param({"id": 9, "slug": ""}, id="slug-empty"),
        ],
    )
    def test_an_entry_that_cannot_address_a_team_is_not_offered(self, malformed):
        """Binding to it would store a pair no check endpoint can be built from."""
        options = build_org_team_options([malformed, {"id": 3, "slug": "sound", "name": "Sound"}])
        assert [option["id"] for option in options] == [3]
