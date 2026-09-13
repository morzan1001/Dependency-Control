"""The deploy order for the member-provenance migration, measured against a real server.

The order is image first, migration second, and it rests on two claims: the new image reads an
unmigrated member without touching them, and the migration rewrites nothing but the bare entries.
Both are executed here, because an order that has either image reject the other's documents costs
the estate its project reads for the length of the rollout.
"""

from datetime import datetime, timezone

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from app.models.team import TeamMember, merge_team_members
from app.repositories.teams import TeamRepository
from scripts.backfill_team_member_sources import (
    EXIT_BARE_MEMBERS_FOUND,
    apply_plan,
    count_bare_members,
    plan_member_stamping,
    run_stamp,
    run_verify,
)

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_GITLAB_INSTANCE = "gl-prod"
_GITHUB_INSTANCE = "gh-cloud"
_STAMPED_GITLAB = team_source(TEAM_SOURCE_GITLAB, _GITLAB_INSTANCE)
_STAMPED_GITHUB = team_source(TEAM_SOURCE_GITHUB, _GITHUB_INSTANCE)

# Three teams as the previous image left them, and one nothing has to do with.
_UNMIGRATED = [
    {
        "_id": "t-edge",
        "name": "GitLab Group: mo/edge",
        "members": [
            {"user_id": "u-ada", "role": "admin", "source": TEAM_SOURCE_GITLAB},
            {"user_id": "u-eve", "role": "member", "source": "manual"},
            {"user_id": "u-legacy", "role": "member"},
        ],
    },
    {
        "_id": "t-payments",
        "name": "Payments Guild",
        "members": [
            {"user_id": "u-bob", "role": "member", "source": TEAM_SOURCE_GITHUB},
            {"user_id": "u-cleo", "role": "member", "source": TEAM_SOURCE_GITLAB},
        ],
    },
    {"_id": "t-atlas", "name": "Atlas", "members": [{"user_id": "u-eve", "role": "admin", "source": "manual"}]},
]


async def _seed(db) -> None:
    for team in _UNMIGRATED:
        await db.teams.insert_one({**team, "members": [dict(member) for member in team["members"]]})
    await db.gitlab_instances.insert_one({"_id": _GITLAB_INSTANCE, "sync_teams": True})
    await db.gitlab_instances.insert_one({"_id": "gl-legacy", "sync_teams": False})
    await db.github_instances.insert_one({"_id": _GITHUB_INSTANCE, "sync_teams": True})


async def _members(db, team_id: str) -> list[dict]:
    return (await db.teams.find_one({"_id": team_id}))["members"]


async def test_the_new_image_reads_an_unmigrated_team_and_claims_none_of_its_members(db):
    """Why the image may go first: a bare value belongs to no instance, so every sync passes it by
    and the estate is simply un-refreshed until the migration runs."""
    await _seed(db)

    team = await TeamRepository(db).get_by_id("t-edge")
    assert [member.source for member in team.members] == [TEAM_SOURCE_GITLAB, "manual", "manual"]

    stored = await _members(db, "t-edge")
    for source in (_STAMPED_GITLAB, team_source(TEAM_SOURCE_GITLAB, "gl-legacy")):
        assert merge_team_members(stored, [], source) == stored


async def test_the_migration_stamps_the_bare_entries_and_nothing_else(db):
    await _seed(db)

    counts = await run_stamp(db, batch_size=10, sleep_ms=0, execute=True)

    assert (counts.teams_planned, counts.teams_matched, counts.members_planned) == (2, 2, 3)
    assert await _members(db, "t-edge") == [
        {"user_id": "u-ada", "role": "admin", "source": _STAMPED_GITLAB},
        {"user_id": "u-eve", "role": "member", "source": "manual"},
        {"user_id": "u-legacy", "role": "member"},
    ]
    assert await _members(db, "t-payments") == [
        {"user_id": "u-bob", "role": "member", "source": _STAMPED_GITHUB},
        {"user_id": "u-cleo", "role": "member", "source": _STAMPED_GITLAB},
    ]
    assert await _members(db, "t-atlas") == _UNMIGRATED[2]["members"]


async def test_a_member_added_during_the_pass_is_not_overwritten_by_it(db):
    """The write addresses one array entry at a time rather than replacing the array, so a member
    an admin adds between the read and the write is still there afterwards."""
    await _seed(db)
    stored = await db.teams.find({}, {"_id": 1, "members.source": 1}).to_list(None)
    added_at = datetime.now(timezone.utc)
    await TeamRepository(db).add_member("t-edge", TeamMember(user_id="u-new").model_dump(), added_at)

    await apply_plan(db, plan_member_stamping(stored, {TEAM_SOURCE_GITLAB: _GITLAB_INSTANCE}))

    assert [member["user_id"] for member in await _members(db, "t-edge")] == [
        "u-ada",
        "u-eve",
        "u-legacy",
        "u-new",
    ]


async def test_the_gate_answers_only_once_nothing_is_bare(db):
    await _seed(db)

    assert await run_verify(db) == EXIT_BARE_MEMBERS_FOUND

    await run_stamp(db, batch_size=10, sleep_ms=0, execute=True)

    assert await count_bare_members(db) == 0
    assert await run_verify(db) == 0
    assert (await run_stamp(db, batch_size=10, sleep_ms=0, execute=False)).teams_planned == 0
