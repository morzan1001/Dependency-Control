"""The repository→team tiebreak (design §5). Fixtures mirror GET /repos/{owner}/{repo}/teams."""

from itertools import permutations
from typing import Any, ClassVar

import pytest

from app.services.github import build_team_depth_map, select_github_team


def _team(
    team_id: int,
    slug: str,
    *,
    permission: str = "pull",
    permissions: dict[str, bool] | None = None,
    access_source: str | None = None,
    parent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    team: dict[str, Any] = {
        "id": team_id,
        "node_id": f"T_kwDO{team_id}",
        "url": f"https://api.github.com/organizations/1/team/{team_id}",
        "html_url": f"https://github.com/orgs/acme/teams/{slug}",
        "name": slug.replace("-", " ").title(),
        "slug": slug,
        "description": None,
        "privacy": "closed",
        "notification_setting": "notifications_enabled",
        "permission": permission,
        "parent": parent,
    }
    # Both are optional on the response: absent keys, never nulls.
    if permissions is not None:
        team["permissions"] = permissions
    if access_source is not None:
        team["access_source"] = access_source
    return team


_PARENT_PLATFORM = {"id": 1, "node_id": "T_kwDO1", "name": "Platform", "slug": "platform"}

# The legacy `permission` string collapses maintain onto push, so only the object separates these two.
_LEGACY_PUSH = {"pull": True, "triage": True, "push": True, "maintain": False, "admin": False}
_LEGACY_PUSH_WITH_MAINTAIN = {"pull": True, "triage": True, "push": True, "maintain": True, "admin": False}

_PERMISSION_LADDER = ["pull", "triage", "push", "maintain", "admin"]


def _permissions_up_to(level: str) -> dict[str, bool]:
    """The object GitHub sends for a team at `level`: every weaker permission is true as well."""
    return {name: _PERMISSION_LADDER.index(name) <= _PERMISSION_LADDER.index(level) for name in _PERMISSION_LADDER}

_CASES = [
    pytest.param(
        [_team(1, "org-wide", access_source="organization"), _team(2, "direct", access_source="direct")],
        None,
        "direct",
        id="rule1-direct-beats-organization",
    ),
    pytest.param(
        [_team(1, "org-wide", access_source="organization"), _team(2, "unstated")],
        None,
        "unstated",
        id="rule1-absent-beats-organization",
    ),
    pytest.param(
        [_team(1, "enterprise-wide", access_source="enterprise"), _team(2, "unstated")],
        None,
        "unstated",
        id="rule1-absent-beats-enterprise",
    ),
    pytest.param(
        [_team(1, "unstated"), _team(2, "direct", access_source="direct")],
        None,
        "direct",
        id="rule1-direct-beats-absent",
    ),
    pytest.param(
        [
            _team(1, "direct-shallow", access_source="direct"),
            _team(2, "org-deep", access_source="organization", parent=_PARENT_PLATFORM),
        ],
        {1: 0, 2: 1},
        "direct-shallow",
        id="rule1-outranks-rule2-depth",
    ),
    pytest.param(
        [_team(1, "future-source", access_source="scim_provisioned"), _team(2, "direct", access_source="direct")],
        None,
        "direct",
        id="rule1-an-unrecognised-source-loses-to-direct",
    ),
    pytest.param(
        [_team(1, "future-source", access_source="scim_provisioned"), _team(2, "unstated")],
        None,
        "unstated",
        id="rule1-an-unrecognised-source-ranks-below-an-absent-one",
    ),
    pytest.param(
        [
            _team(1, "direct-reader", permission="pull", access_source="direct"),
            _team(2, "org-admin", permission="admin", access_source="organization"),
        ],
        None,
        "direct-reader",
        id="rule1-outranks-rule3-permission",
    ),
    pytest.param(
        [_team(1, "platform"), _team(2, "payments", parent=_PARENT_PLATFORM)],
        {1: 0, 2: 1},
        "payments",
        id="rule2-deeper-team-wins",
    ),
    pytest.param(
        [_team(1, "platform", permission="admin"), _team(2, "payments", parent=_PARENT_PLATFORM)],
        {1: 0, 2: 1},
        "payments",
        id="rule2-outranks-rule3-permission",
    ),
    pytest.param(
        [_team(1, "platform", permission="admin"), _team(2, "payments", parent=_PARENT_PLATFORM)],
        None,
        "platform",
        id="rule2-skipped-without-a-depth-map-falls-through-to-permission",
    ),
    pytest.param(
        [_team(1, "readers", permission="pull"), _team(2, "owners", permission="admin")],
        None,
        "owners",
        id="rule3-permission-string",
    ),
    pytest.param(
        [
            _team(1, "pushers", permission="push", permissions=_LEGACY_PUSH),
            _team(2, "maintainers", permission="push", permissions=_LEGACY_PUSH_WITH_MAINTAIN),
        ],
        None,
        "maintainers",
        id="rule3-permissions-object-outranks-the-legacy-string",
    ),
    pytest.param(
        # A custom repository role puts its own name in `permission`.
        [_team(1, "custom-role", permission="triage_and_deploy"), _team(2, "readers", permission="pull")],
        None,
        "readers",
        id="rule3-an-unrecognised-permission-ranks-below-pull",
    ),
    pytest.param(
        [
            _team(42, "beta", permission="push", access_source="direct"),
            _team(7, "alpha", permission="push", access_source="direct"),
        ],
        {42: 1, 7: 1},
        "alpha",
        id="rule4-lowest-id-breaks-the-tie-rules-1-to-3-cannot",
    ),
]


@pytest.mark.parametrize(("candidates", "depth_map", "expected_slug"), _CASES)
def test_the_tiebreak_picks_one_team(candidates, depth_map, expected_slug):
    winner = select_github_team(candidates, depth_map)
    assert winner is not None
    assert winner["slug"] == expected_slug


@pytest.mark.parametrize(
    ("lower", "higher"),
    [("pull", "triage"), ("triage", "push"), ("push", "maintain"), ("maintain", "admin")],
)
def test_the_permission_ladder_orders_every_adjacent_pair(lower, higher):
    candidates = [
        _team(1, "lower", permissions=_permissions_up_to(lower)),
        _team(2, "higher", permissions=_permissions_up_to(higher)),
    ]
    winner = select_github_team(candidates, None)
    assert winner is not None
    assert winner["slug"] == "higher"


def test_no_candidates_resolve_to_no_team():
    assert select_github_team([], None) is None


@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param({"slug": "broken", "permission": "admin"}, id="id-missing"),
        pytest.param({"id": None, "slug": "broken", "permission": "admin"}, id="id-null"),
        pytest.param({"id": "MDQ6VGVhbTE=", "slug": "broken", "permission": "admin"}, id="id-not-a-number"),
    ],
)
def test_a_team_whose_id_cannot_be_ordered_by_is_skipped_rather_than_fatal(malformed):
    """`id` is required and numeric on the response; a malformed entry must not take the repository down."""
    assert select_github_team([malformed], None) is None

    winner = select_github_team([malformed, _team(5, "sound")], None)
    assert winner is not None
    assert winner["slug"] == "sound"


class TestStability:
    """Two syncs of one repository must not flip the project's team."""

    _CANDIDATES: ClassVar[list[dict[str, Any]]] = [
        _team(42, "beta", permission="push", access_source="direct"),
        _team(7, "alpha", permission="push", access_source="direct"),
        _team(19, "gamma", permission="push", access_source="direct"),
    ]

    def test_the_same_candidate_set_yields_the_same_winner_twice(self):
        first = select_github_team(list(self._CANDIDATES), {42: 1, 7: 1, 19: 1})
        second = select_github_team(list(self._CANDIDATES), {42: 1, 7: 1, 19: 1})
        assert first["slug"] == second["slug"] == "alpha"

    def test_the_winner_does_not_depend_on_the_order_github_returned(self):
        winners = {select_github_team(list(order), None)["slug"] for order in permutations(self._CANDIDATES)}
        assert winners == {"alpha"}


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
