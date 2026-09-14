"""One sync's write over a team several syncs and several people contribute members to.

The subset a sync may replace is named by the provenance tag it writes, and the server is what
applies that rule: the write is a pipeline over the array as stored. Each case therefore runs
against a real server as well as the double, because a double that reads ``$filter`` more
generously than Percona does would green-light a write that strips a member in production.
"""

import pytest

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_SOURCE_GITHUB, team_source
from app.models.team import GitHubTeamBinding, Team, TeamMember
from app.repositories.teams import MemberSubset, TeamRepository
from tests.mocks.fake_mongo import FakeDatabase

_TEAM_ID = "t-pay"
_OWN = team_source(TEAM_SOURCE_GITHUB, "gh-inst-a")
_THEIRS = team_source(TEAM_SOURCE_GITHUB, "gh-inst-b")
_ANOTHER_PROVIDER = team_source("gitlab", "gl-inst-a")

_MANUAL = {"user_id": "u-manual", "role": "admin", "source": "manual"}
_BINDING = GitHubTeamBinding(instance_id="gh-inst-a", org="acme", external_id=4711, slug="payments")

_CASES = [
    pytest.param(
        [_MANUAL],
        [],
        [_MANUAL],
        id="a hand-added member is never removed by a sync",
    ),
    pytest.param(
        [{"user_id": "u-gl", "role": "admin", "source": _ANOTHER_PROVIDER}],
        [],
        [{"user_id": "u-gl", "role": "admin", "source": _ANOTHER_PROVIDER}],
        id="another provider's member keeps the provenance that can refresh them",
    ),
    pytest.param(
        [{"user_id": "u-b", "role": "member", "source": _THEIRS}],
        [TeamMember(user_id="u-a", source=_OWN)],
        [
            {"user_id": "u-b", "role": "member", "source": _THEIRS},
            {"user_id": "u-a", "role": TEAM_ROLE_MEMBER, "source": _OWN},
        ],
        id="another instance of the same provider keeps its subset",
    ),
    pytest.param(
        [
            {"user_id": "u-old", "role": "member", "source": TEAM_SOURCE_GITHUB},
            {"user_id": "u-older", "role": "member"},
        ],
        [],
        [
            {"user_id": "u-old", "role": "member", "source": TEAM_SOURCE_GITHUB},
            {"user_id": "u-older", "role": "member"},
        ],
        id="a member whose source names no instance is nobody's to replace",
    ),
    pytest.param(
        [{"user_id": "u-gone", "role": "member", "source": _OWN}],
        [],
        [],
        id="a member who left the group disappears",
    ),
    pytest.param(
        [{"user_id": "u-1", "role": "member", "source": _OWN}],
        [TeamMember(user_id="u-1", role="admin", source=_OWN)],
        [{"user_id": "u-1", "role": "admin", "source": _OWN}],
        id="the resolved entry wins over the stored one",
    ),
    pytest.param(
        [{"user_id": "u-1", "role": "member", "source": "manual"}],
        [TeamMember(user_id="u-1", role="admin", source=_OWN)],
        [{"user_id": "u-1", "role": "admin", "source": _OWN}],
        id="a hand-added member the group also holds is not duplicated",
    ),
]


async def _assert_the_write_replaces_only_its_own_subset(db, stored, resolved, expected) -> None:
    repo = TeamRepository(db)
    await repo.create(Team(id=_TEAM_ID, name="Payments Guild", bindings=[_BINDING]))
    await db.teams.update_one({"_id": _TEAM_ID}, {"$set": {"members": [dict(m) for m in stored]}})

    await repo.update_with_binding(
        _TEAM_ID,
        {},
        _BINDING.key,
        {},
        MemberSubset(_OWN, [member.model_dump() for member in resolved]),
    )

    assert (await repo.get_raw_by_id(_TEAM_ID))["members"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(("stored", "resolved", "expected"), _CASES)
async def test_the_write_replaces_only_its_own_subset(stored, resolved, expected):
    await _assert_the_write_replaces_only_its_own_subset(FakeDatabase(), stored, resolved, expected)


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize(("stored", "resolved", "expected"), _CASES)
async def test_the_write_replaces_only_its_own_subset_on_real_mongo(db, stored, resolved, expected):
    await _assert_the_write_replaces_only_its_own_subset(db, stored, resolved, expected)
