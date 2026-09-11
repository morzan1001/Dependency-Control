"""The candidate→team tiebreak. Fixtures mirror the entries built from the team/repository check."""

from itertools import permutations
from typing import Any, ClassVar

import pytest

from app.services.github import (
    build_org_team_options,
    build_team_depth_map,
    build_team_slug_map,
    select_github_team,
)

_PERMISSION_LADDER = ["pull", "triage", "push", "maintain", "admin"]


def _permissions_up_to(level: str) -> dict[str, bool]:
    """The object GitHub sends for a team at `level`: every weaker permission is true as well."""
    return {name: _PERMISSION_LADDER.index(name) <= _PERMISSION_LADDER.index(level) for name in _PERMISSION_LADDER}


def _candidate(
    team_id: int,
    slug: str,
    *,
    permission: str = "pull",
    permissions: dict[str, bool] | None = None,
) -> dict[str, Any]:
    return {
        "id": team_id,
        "slug": slug,
        "permissions": _permissions_up_to(permission) if permissions is None else permissions,
        "role_name": permission,
    }


_CASES = [
    pytest.param(
        [_candidate(1, "platform"), _candidate(2, "payments")],
        {1: 0, 2: 1},
        "payments",
        id="rule2-deeper-team-wins",
    ),
    pytest.param(
        [_candidate(1, "platform", permission="admin"), _candidate(2, "payments")],
        {1: 0, 2: 1},
        "payments",
        id="rule2-outranks-rule3-permission",
    ),
    pytest.param(
        [_candidate(1, "platform", permission="admin"), _candidate(2, "payments")],
        {},
        "platform",
        id="rule2-skipped-when-no-team-is-nested-falls-through-to-permission",
    ),
    pytest.param(
        [_candidate(1, "readers", permission="pull"), _candidate(2, "owners", permission="admin")],
        {},
        "owners",
        id="rule3-strongest-permission-wins",
    ),
    pytest.param(
        # The lower id belongs to the weaker team, so only rule 3 can pick the stated one.
        [_candidate(2, "stated", permission="pull"), _candidate(1, "unstated", permissions={})],
        {},
        "stated",
        id="rule3-a-payload-stating-no-permission-ranks-below-pull",
    ),
    pytest.param(
        [_candidate(42, "beta", permission="push"), _candidate(7, "alpha", permission="push")],
        {42: 1, 7: 1},
        "alpha",
        id="rule4-lowest-id-breaks-the-tie-rules-2-and-3-cannot",
    ),
]


@pytest.mark.parametrize(("candidates", "depth_map", "expected_slug"), _CASES)
def test_the_tiebreak_picks_one_team(candidates, depth_map, expected_slug):
    winner = select_github_team(candidates, depth_map)
    assert winner is not None
    assert winner["slug"] == expected_slug


@pytest.mark.parametrize(
    "unstated",
    [
        pytest.param({"id": 1, "slug": "unstated", "role_name": "pull"}, id="permissions-absent"),
        pytest.param({"id": 1, "slug": "unstated", "permissions": None}, id="permissions-null"),
        pytest.param({"id": 1, "slug": "unstated", "permissions": ["pull"]}, id="permissions-not-an-object"),
    ],
)
def test_a_body_carrying_no_permissions_object_ranks_below_the_weakest_stated_one(unstated):
    """A 200 without the repository media type omits `permissions`; ranking it as pull would let it
    outrank a team that really holds push on the lower id."""
    winner = select_github_team([unstated, _candidate(2, "stated", permission="pull")], {})
    assert winner is not None
    assert winner["slug"] == "stated"


@pytest.mark.parametrize(
    ("lower", "higher"),
    [("pull", "triage"), ("triage", "push"), ("push", "maintain"), ("maintain", "admin")],
)
def test_the_permission_ladder_orders_every_adjacent_pair(lower, higher):
    candidates = [_candidate(1, "lower", permission=lower), _candidate(2, "higher", permission=higher)]
    winner = select_github_team(candidates, {})
    assert winner is not None
    assert winner["slug"] == "higher"


def test_no_candidates_resolve_to_no_team():
    assert select_github_team([], {}) is None


def test_access_source_is_no_longer_an_input():
    """The check endpoint reports none, so the tiebreak must not rank on a value it cannot see."""
    direct = _candidate(9, "direct", permission="pull")
    direct["access_source"] = "direct"
    inherited = _candidate(1, "inherited", permission="admin")
    inherited["access_source"] = "organization"

    winner = select_github_team([direct, inherited], {})
    assert winner is not None
    assert winner["slug"] == "inherited"


@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param({"slug": "broken", "permissions": _permissions_up_to("admin")}, id="id-missing"),
        pytest.param({"id": None, "slug": "broken", "permissions": _permissions_up_to("admin")}, id="id-null"),
        pytest.param(
            {"id": "MDQ6VGVhbTE=", "slug": "broken", "permissions": _permissions_up_to("admin")},
            id="id-not-a-number",
        ),
    ],
)
def test_a_team_whose_id_cannot_be_ordered_by_is_skipped_rather_than_fatal(malformed):
    """`id` is required and numeric on the response; a malformed entry must not take the repository down."""
    assert select_github_team([malformed], {}) is None

    winner = select_github_team([malformed, _candidate(5, "sound")], {})
    assert winner is not None
    assert winner["slug"] == "sound"


@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param({"id": 1, "permissions": _permissions_up_to("admin")}, id="slug-missing"),
        pytest.param({"id": 1, "slug": None, "permissions": _permissions_up_to("admin")}, id="slug-null"),
        pytest.param({"id": 1, "slug": "", "permissions": _permissions_up_to("admin")}, id="slug-empty"),
    ],
)
def test_a_team_that_cannot_be_addressed_by_slug_is_skipped_rather_than_fatal(malformed):
    """The members endpoint is slug-addressed, so an unaddressable winner is no winner at all."""
    assert select_github_team([malformed], {}) is None

    # The malformed team outranks the sound one on permission and on id, so only the filter saves it.
    winner = select_github_team([malformed, _candidate(5, "sound")], {})
    assert winner is not None
    assert winner["slug"] == "sound"


class TestStability:
    """Two syncs of one repository must not flip the project's team."""

    _CANDIDATES: ClassVar[list[dict[str, Any]]] = [
        _candidate(42, "beta", permission="push"),
        _candidate(7, "alpha", permission="push"),
        _candidate(19, "gamma", permission="push"),
    ]

    def test_the_same_candidate_set_yields_the_same_winner_twice(self):
        first = select_github_team(list(self._CANDIDATES), {42: 1, 7: 1, 19: 1})
        second = select_github_team(list(self._CANDIDATES), {42: 1, 7: 1, 19: 1})
        assert first["slug"] == second["slug"] == "alpha"

    def test_the_winner_does_not_depend_on_the_order_the_checks_answered_in(self):
        winners = {select_github_team(list(order), {})["slug"] for order in permutations(self._CANDIDATES)}
        assert winners == {"alpha"}


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


class TestDepthMap:
    def test_walks_the_parent_chain(self):
        org_teams = [
            {"id": 1, "slug": "platform", "parent": None},
            {"id": 2, "slug": "payments", "parent": {"id": 1, "slug": "platform"}},
            {"id": 3, "slug": "cards", "parent": {"id": 2, "slug": "payments"}},
        ]
        assert build_team_depth_map(org_teams) == {1: 0, 2: 1, 3: 2}

    def test_a_parent_outside_the_list_stops_the_walk(self):
        org_teams = [{"id": 2, "slug": "payments", "parent": {"id": 99, "slug": "invisible"}}]
        assert build_team_depth_map(org_teams) == {2: 0}

    def test_a_self_referential_parent_terminates(self):
        org_teams = [{"id": 7, "slug": "loop", "parent": {"id": 7, "slug": "loop"}}]
        assert build_team_depth_map(org_teams) == {7: 0}

    def test_a_mutual_parent_cycle_terminates(self):
        org_teams = [
            {"id": 1, "slug": "a", "parent": {"id": 2, "slug": "b"}},
            {"id": 2, "slug": "b", "parent": {"id": 1, "slug": "a"}},
        ]
        assert build_team_depth_map(org_teams) == {1: 1, 2: 1}

    def test_a_parent_id_of_another_type_still_links_the_chain(self):
        """An uncoerced parent id silently demotes the nested team to depth 0 — a wrong answer, not an error."""
        org_teams = [
            {"id": 1, "slug": "platform", "parent": None},
            {"id": 2, "slug": "payments", "parent": {"id": "1", "slug": "platform"}},
        ]
        assert build_team_depth_map(org_teams) == {1: 0, 2: 1}

    @pytest.mark.parametrize(
        "malformed",
        [
            pytest.param({"slug": "nameless", "parent": None}, id="id-missing"),
            pytest.param({"id": None, "slug": "nulled", "parent": None}, id="id-null"),
            pytest.param({"id": "MDQ6VGVhbTE=", "slug": "opaque", "parent": None}, id="id-not-a-number"),
        ],
    )
    def test_a_team_whose_id_cannot_be_ordered_by_is_left_out(self, malformed):
        org_teams = [malformed, {"id": 3, "slug": "sound", "parent": None}]
        assert build_team_depth_map(org_teams) == {3: 0}


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
