"""One sync's write over a team several syncs and several people contribute members to.

The subset a sync may replace is named by the provenance tag it writes, and the server is what
applies that rule: the write is a pipeline over the array as stored. Each case therefore runs
against a real server as well as the double, because a double that reads ``$filter`` more
generously than Percona does would green-light a write that strips a member in production.
"""

from datetime import datetime, timezone

import pytest

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_SOURCE_GITHUB, team_source
from app.models.team import GitHubTeamBinding, Team, TeamMember
from app.repositories.teams import MemberSubset, TeamRepository
from app.services.github import GitHubService, _RepositoryHolder
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance

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
        [{"user_id": "u-1", "role": "member", "source": "manual"}],
        id="a hand-added member the group also holds keeps the entry an admin gave them",
    ),
    pytest.param(
        [{"user_id": "u-1", "role": "member", "source": _THEIRS}],
        [TeamMember(user_id="u-1", role="admin", source=_OWN)],
        [{"user_id": "u-1", "role": "member", "source": _THEIRS}],
        id="a member another instance holds is not duplicated",
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


_ADA = {"user_id": "u-ada", "role": "member", "source": _OWN}

_REFRESH_CASES = [
    pytest.param(
        [_ADA], [TeamMember(user_id="u-ada", source=_OWN)], "Payments Guild", "payments", False, id="unchanged"
    ),
    pytest.param(
        [_MANUAL, _ADA],
        [TeamMember(user_id="u-ada", source=_OWN)],
        "Payments Guild",
        "payments",
        False,
        id="unchanged beside a hand-added member",
    ),
    pytest.param(
        [_ADA],
        [TeamMember(user_id="u-ada", role="admin", source=_OWN)],
        "Payments Guild",
        "payments",
        True,
        id="a changed role",
    ),
    pytest.param([_ADA], [], "Payments Guild", "payments", True, id="a member who left"),
    pytest.param(
        [_ADA],
        [TeamMember(user_id="u-ada", source=_OWN)],
        "GitHub Team: acme/pay-old",
        "pay-old",
        True,
        id="a renamed group with unchanged members",
    ),
]


async def _assert_only_a_change_is_written(db, stored, resolved, name, slug, written) -> None:
    repo = TeamRepository(db)
    binding = GitHubTeamBinding(instance_id="gh-inst-a", org="acme", external_id=4711, slug=slug)
    await repo.create(Team(id=_TEAM_ID, name=name, bindings=[binding]))
    long_ago = datetime(2026, 1, 1, tzinfo=timezone.utc)
    await db.teams.update_one({"_id": _TEAM_ID}, {"$set": {"members": stored, "updated_at": long_ago}})
    team = await repo.get_raw_by_id(_TEAM_ID)
    before = team["updated_at"]

    service = GitHubService(make_github_instance(id="gh-inst-a"))
    await service._refresh_team(repo, "acme", _RepositoryHolder(team, 4711, "payments"), resolved)

    # Every CI job re-resolves the same members, so only a change may touch the document.
    assert ((await repo.get_raw_by_id(_TEAM_ID))["updated_at"] != before) is written


@pytest.mark.asyncio
@pytest.mark.parametrize(("stored", "resolved", "name", "slug", "written"), _REFRESH_CASES)
async def test_only_a_change_is_written(stored, resolved, name, slug, written):
    await _assert_only_a_change_is_written(FakeDatabase(), stored, resolved, name, slug, written)


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize(("stored", "resolved", "name", "slug", "written"), _REFRESH_CASES)
async def test_only_a_change_is_written_on_real_mongo(db, stored, resolved, name, slug, written):
    await _assert_only_a_change_is_written(db, stored, resolved, name, slug, written)
