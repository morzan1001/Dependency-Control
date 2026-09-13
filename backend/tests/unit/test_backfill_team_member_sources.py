"""The migration that gives every member provenance value its instance, and the gate on it.

The gate has to be exactly as strict as the migration itself, so the two are checked against one
corpus rather than each other's description. It also has to survive the runbook: an operator who
pastes the mongosh spelling must run the filter the script runs.
"""

import json
import pathlib

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from scripts.backfill_team_member_sources import (
    EXIT_BARE_MEMBERS_FOUND,
    bare_member_filter,
    count_bare_members,
    plan_member_stamping,
    resolve_instances,
    run_stamp,
    run_verify,
)
from scripts.backfill_team_source_instances import InstanceNotResolvable
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongo_array_cases import BARE_MEMBER_TEAMS

_RUNBOOK = pathlib.Path(__file__).parents[2] / "scripts" / "README-deploy-member-provenance.md"
_COUNT_CALL = "db.teams.countDocuments("
_GATE_SECTION = "### 4a."

_GITLAB_INSTANCE = "gl-inst-a"
_GITHUB_INSTANCE = "gh-inst-a"
_INSTANCES = {TEAM_SOURCE_GITLAB: _GITLAB_INSTANCE, TEAM_SOURCE_GITHUB: _GITHUB_INSTANCE}
_GITLAB_A = team_source(TEAM_SOURCE_GITLAB, _GITLAB_INSTANCE)
_GITHUB_A = team_source(TEAM_SOURCE_GITHUB, _GITHUB_INSTANCE)


async def _seeded(*teams) -> FakeDatabase:
    db = FakeDatabase()
    for team in teams:
        await db.teams.insert_one(team)
    return db


async def _with_instances(db: FakeDatabase, *, gitlab: int = 1, github: int = 1) -> FakeDatabase:
    for index in range(gitlab):
        await db.gitlab_instances.insert_one({"_id": f"gl-inst-{chr(ord('a') + index)}", "sync_teams": True})
    for index in range(github):
        await db.github_instances.insert_one({"_id": f"gh-inst-{chr(ord('a') + index)}", "sync_teams": True})
    return db


def test_a_bare_value_gains_the_instance_that_added_the_member():
    teams = [{"_id": "t", "members": [{"user_id": "u", "source": "gitlab"}]}]

    (update,) = plan_member_stamping(teams, _INSTANCES)

    assert (update.stamped, update.members) == ({TEAM_SOURCE_GITLAB: _GITLAB_A}, 1)


def test_manual_is_never_rewritten():
    teams = [{"_id": "t", "members": [{"user_id": "u1", "source": "manual"}, {"user_id": "u2", "source": "gitlab"}]}]

    (update,) = plan_member_stamping(teams, _INSTANCES)

    assert (update.stamped, update.members) == ({TEAM_SOURCE_GITLAB: _GITLAB_A}, 1)


def test_a_member_with_no_source_at_all_is_left_alone():
    """The model reads an absent value as manual, so writing one changes no behaviour and would
    claim a human added a member whose origin nothing records."""
    assert plan_member_stamping([{"_id": "t", "members": [{"user_id": "u"}]}], _INSTANCES) == []


def test_a_value_already_naming_an_instance_is_left_exactly_as_stored():
    """Re-attributing one would move a member between instances, which no evidence supports."""
    other = team_source(TEAM_SOURCE_GITLAB, "gl-inst-z")

    assert plan_member_stamping([{"_id": "t", "members": [{"user_id": "u", "source": other}]}], _INSTANCES) == []


def test_a_team_with_no_members_is_left_alone():
    assert plan_member_stamping([{"_id": "t", "members": []}, {"_id": "t2"}], _INSTANCES) == []


def test_each_provider_gets_its_own_instance_and_every_entry_is_counted():
    teams = [
        {
            "_id": "t",
            "members": [
                {"user_id": "u1", "source": "gitlab"},
                {"user_id": "u2", "source": "gitlab"},
                {"user_id": "u3", "source": "github"},
            ],
        }
    ]

    (update,) = plan_member_stamping(teams, _INSTANCES)

    assert update.stamped == {TEAM_SOURCE_GITLAB: _GITLAB_A, TEAM_SOURCE_GITHUB: _GITHUB_A}
    assert update.members == 3


@pytest.mark.asyncio
async def test_the_gate_agrees_with_the_migration_over_the_whole_corpus():
    """A count of 0 has to mean a re-run of the migration would plan nothing, or it proves nothing."""
    teams = [{"_id": f"t{index}", **team} for index, team in enumerate(BARE_MEMBER_TEAMS)]
    db = await _seeded(*teams)

    selected = sorted(team["_id"] for team in await db.teams.find(bare_member_filter(), {"_id": 1}).to_list(None))

    assert selected == sorted(update.team_id for update in plan_member_stamping(teams, _INSTANCES))
    assert selected, "the corpus must contain unmigrated documents, or the comparison is vacuous"


@pytest.mark.asyncio
async def test_verify_reports_success_only_on_a_migrated_database():
    migrated = {"_id": "ok", "members": [{"user_id": "u", "source": _GITLAB_A}]}
    bare = {"_id": "bare", "members": [{"user_id": "u", "source": "gitlab"}]}

    assert await run_verify(await _seeded(migrated)) == 0
    assert await run_verify(await _seeded(migrated, bare)) == EXIT_BARE_MEMBERS_FOUND


@pytest.mark.asyncio
async def test_two_syncing_instances_of_one_provider_abort_the_run():
    """Either instance could have added the member, and the wrong one hands them to its next sync
    to drop."""
    db = await _with_instances(
        await _seeded({"_id": "t", "members": [{"user_id": "u", "source": "gitlab"}]}), gitlab=2
    )

    with pytest.raises(InstanceNotResolvable):
        await resolve_instances(db)


@pytest.mark.asyncio
async def test_a_provider_with_no_bare_values_needs_no_instance():
    """A single-provider installation must not be blocked by the other provider having none."""
    db = await _seeded({"_id": "t", "members": [{"user_id": "u", "source": "gitlab"}]})
    await db.gitlab_instances.insert_one({"_id": _GITLAB_INSTANCE, "sync_teams": True})

    assert await resolve_instances(db) == {TEAM_SOURCE_GITLAB: _GITLAB_INSTANCE}


@pytest.mark.asyncio
async def test_execute_migrates_every_selected_team_and_is_idempotent():
    db = await _with_instances(
        await _seeded(*[{"_id": f"t{index}", **team} for index, team in enumerate(BARE_MEMBER_TEAMS)])
    )

    counts = await run_stamp(db, batch_size=2, sleep_ms=0, execute=True)

    assert (counts.teams_planned, counts.teams_matched, counts.members_planned) == (4, 4, 6)
    assert await count_bare_members(db) == 0
    assert (await run_stamp(db, batch_size=2, sleep_ms=0, execute=False)).teams_planned == 0


@pytest.mark.asyncio
async def test_only_the_bare_entries_of_a_mixed_team_are_rewritten():
    """The write addresses members one entry at a time, so everyone else's is left byte for byte."""
    db = await _with_instances(
        await _seeded(
            {
                "_id": "t",
                "members": [
                    {"user_id": "u-manual", "role": "admin", "source": "manual"},
                    {"user_id": "u-none", "role": "member"},
                    {"user_id": "u-other", "role": "member", "source": team_source(TEAM_SOURCE_GITLAB, "gl-inst-z")},
                    {"user_id": "u-bare", "role": "member", "source": "gitlab"},
                ],
            }
        )
    )

    await run_stamp(db, batch_size=10, sleep_ms=0, execute=True)

    assert (await db.teams.find_one({"_id": "t"}))["members"] == [
        {"user_id": "u-manual", "role": "admin", "source": "manual"},
        {"user_id": "u-none", "role": "member"},
        {"user_id": "u-other", "role": "member", "source": team_source(TEAM_SOURCE_GITLAB, "gl-inst-z")},
        {"user_id": "u-bare", "role": "member", "source": _GITLAB_A},
    ]


def _published_filters() -> list[dict]:
    """Every ``countDocuments`` argument the runbook's gate section publishes, in order."""
    body = _RUNBOOK.read_text()
    cursor = body.index(_GATE_SECTION)
    # Bounded to the gate's own section: later sections publish counts of their own, and reading
    # those as gate filters would compare the gate against a query it never runs.
    body = body[: body.index("\n## ", cursor)]
    filters = []
    while (call := body.find(_COUNT_CALL, cursor)) != -1:
        start = call + len(_COUNT_CALL)
        end = body.index("\n})", start) + 2  # keep the closing brace, drop the call's own paren
        filters.append(json.loads(body[start:end]))
        cursor = end
    return filters


def test_the_runbook_publishes_the_filter_the_script_runs():
    """An operator pastes the mongosh spelling; if it drifts from the script it checks nothing."""
    assert _published_filters() == [bare_member_filter()]
