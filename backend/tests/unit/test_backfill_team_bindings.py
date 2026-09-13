"""The migration that moves a team's binding into the array, and the gate that releases it.

The gate has to be exactly as strict as the contract pass itself, so the two are checked against
one corpus rather than each other's description. It also has to survive the runbook: an operator
who pastes the mongosh spelling must run the filter the script runs.
"""

import json
import pathlib

import pytest

from app.models.team import GitHubTeamBinding, GitLabGroupBinding
from scripts.backfill_team_bindings import (
    EXIT_SCALAR_BINDINGS_FOUND,
    SCALAR_FIELDS,
    count_scalar_bindings,
    derive_bindings,
    plan_bindings,
    run_move,
    run_verify,
    scalar_binding_filter,
)
from tests.mocks.fake_mongo import FakeDatabase

_RUNBOOK = pathlib.Path(__file__).parents[2] / "scripts" / "README-deploy-team-bindings.md"
_COUNT_CALL = "db.teams.countDocuments("
_GATE_SECTION = "### 7b."

_GITHUB = GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=4711, slug="payments").model_dump()
_GITLAB = GitLabGroupBinding(instance_id="gl-1", external_id=77, path="mo/edge").model_dump()

# Every shape the estate holds, as one corpus the plan and the gate are both measured against.
_CORPUS: list[dict] = [
    # A manual team: no binding, seven explicit nulls, which is what every team document carries.
    {"name": "Atlas", **dict.fromkeys(SCALAR_FIELDS)},
    {
        "name": "Payments",
        **dict.fromkeys(SCALAR_FIELDS),
        "github_instance_id": "gh-1",
        "github_org": "acme",
        "github_team_id": 4711,
        "github_team_slug": "payments",
    },
    {
        "name": "Edge",
        **dict.fromkeys(SCALAR_FIELDS),
        "gitlab_instance_id": "gl-1",
        "gitlab_group_id": 77,
        "gitlab_group_path": "mo/edge",
    },
    {
        "name": "Both",
        "gitlab_instance_id": "gl-1",
        "gitlab_group_id": 88,
        "github_instance_id": "gh-1",
        "github_org": "acme",
        "github_team_id": 900,
    },
    # An instance with no group number, which startup used to write onto legacy synced teams.
    {"name": "Half", **dict.fromkeys(SCALAR_FIELDS), "gitlab_instance_id": "gl-1"},
    # Already migrated, and carrying no scalar at all.
    {"name": "Migrated", "bindings": [_GITHUB]},
]


async def _seeded(*teams) -> FakeDatabase:
    db = FakeDatabase()
    for index, team in enumerate(teams):
        await db.teams.insert_one({"_id": f"t{index}", **team})
    return db


def _numbered(teams: list[dict]) -> list[dict]:
    return [{"_id": f"t{index}", **team} for index, team in enumerate(teams)]


def test_a_github_binding_moves_whole():
    team = {"_id": "t", "github_instance_id": "gh-1", "github_org": "acme", "github_team_id": 4711,
            "github_team_slug": "payments"}

    assert derive_bindings(team) == [_GITHUB]


def test_a_gitlab_binding_moves_whole():
    team = {"_id": "t", "gitlab_instance_id": "gl-1", "gitlab_group_id": 77, "gitlab_group_path": "mo/edge"}

    assert derive_bindings(team) == [_GITLAB]


def test_a_team_bound_to_both_providers_gains_two_entries():
    (update,) = plan_bindings(
        [
            {
                "_id": "t",
                "gitlab_instance_id": "gl-1",
                "gitlab_group_id": 77,
                "gitlab_group_path": "mo/edge",
                "github_instance_id": "gh-1",
                "github_org": "acme",
                "github_team_id": 4711,
                "github_team_slug": "payments",
            }
        ],
        drop_scalars=False,
    )

    assert update.bindings == [_GITLAB, _GITHUB]


def test_an_instance_with_no_group_number_produces_no_binding():
    """It addresses no group, and storing it would occupy the team's one entry for that instance."""
    assert derive_bindings({"_id": "t", "gitlab_instance_id": "gl-1", "gitlab_group_id": None}) == []
    assert derive_bindings({"_id": "t", "github_instance_id": "gh-1", "github_org": "acme"}) == []


def test_an_entry_the_team_already_holds_is_never_overwritten():
    """The array is what the new image writes; re-deriving over it would undo a live binding."""
    stored = GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=900, slug="cards").model_dump()
    teams = [{"_id": "t", "bindings": [stored], "github_instance_id": "gh-1", "github_org": "acme",
              "github_team_id": 4711, "github_team_slug": "payments"}]

    assert plan_bindings(teams, drop_scalars=False) == []


def test_the_contract_pass_keeps_the_entry_and_sheds_the_scalars():
    stored = GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=900, slug="cards").model_dump()
    teams = [{"_id": "t", "bindings": [stored], "github_instance_id": "gh-1", "github_team_id": 4711}]

    (update,) = plan_bindings(teams, drop_scalars=True)

    assert update.bindings is None
    assert update.unset == ("github_instance_id", "github_team_id")
    assert update.to_update() == {"$unset": {"github_instance_id": "", "github_team_id": ""}}


def test_the_expand_pass_leaves_every_scalar_where_it_is():
    """Both images serve during the rollout, and the previous one reads nothing else."""
    (update,) = plan_bindings(_numbered(_CORPUS)[1:2], drop_scalars=False)

    assert update.unset == ()
    assert update.to_update() == {"$set": {"bindings": [_GITHUB]}}


def test_a_team_carrying_nothing_but_nulls_is_still_contracted():
    """The nulls are fields the model no longer declares; a gate on truth would pass over them."""
    (update,) = plan_bindings([{"_id": "t", **dict.fromkeys(SCALAR_FIELDS)}], drop_scalars=True)

    assert update.unset == SCALAR_FIELDS


def test_a_team_that_never_carried_a_scalar_is_left_alone():
    assert plan_bindings([{"_id": "t", "bindings": [_GITHUB]}], drop_scalars=True) == []


@pytest.mark.asyncio
async def test_the_gate_agrees_with_the_contract_pass_over_the_whole_corpus():
    """A count of 0 has to mean a re-run would plan nothing, or it proves nothing."""
    teams = _numbered(_CORPUS)
    db = await _seeded(*_CORPUS)

    selected = sorted(team["_id"] for team in await db.teams.find(scalar_binding_filter(), {"_id": 1}).to_list(None))

    assert selected == sorted(update.team_id for update in plan_bindings(teams, drop_scalars=True))
    assert selected, "the corpus must contain unmigrated documents, or the comparison is vacuous"


@pytest.mark.asyncio
async def test_verify_reports_success_only_on_a_contracted_database():
    assert await run_verify(await _seeded({"name": "Migrated", "bindings": [_GITHUB]})) == 0
    assert await run_verify(await _seeded(*_CORPUS)) == EXIT_SCALAR_BINDINGS_FOUND


@pytest.mark.asyncio
async def test_verify_answers_to_a_scalar_left_behind_as_null():
    db = await _seeded({"name": "Nearly", "bindings": [_GITHUB], "github_team_slug": None})

    assert await run_verify(db) == EXIT_SCALAR_BINDINGS_FOUND


@pytest.mark.asyncio
async def test_the_two_passes_migrate_the_estate_and_are_each_idempotent():
    db = await _seeded(*_CORPUS)

    planned, matched = await run_move(db, batch_size=2, sleep_ms=0, execute=True, drop_scalars=False)
    # Three of the six describe a binding; the manual team, the half-filled one and the already
    # migrated one describe none.
    assert (planned, matched) == (3, 3)
    assert await run_move(db, batch_size=2, sleep_ms=0, execute=False, drop_scalars=False) == (0, 0)
    # The expand pass writes the array without taking anything out of the gate's scope.
    assert await count_scalar_bindings(db) == len(_CORPUS) - 1

    planned, matched = await run_move(db, batch_size=2, sleep_ms=0, execute=True, drop_scalars=True)
    assert (planned, matched) == (len(_CORPUS) - 1, len(_CORPUS) - 1)
    assert await count_scalar_bindings(db) == 0
    assert await run_move(db, batch_size=2, sleep_ms=0, execute=False, drop_scalars=True) == (0, 0)


@pytest.mark.asyncio
async def test_the_contract_pass_alone_migrates_a_team_that_missed_the_expand_pass():
    """A team an old pod bound during the rollout has scalars and no entry; the second pass is the
    only thing that still reads them."""
    db = await _seeded(_CORPUS[1])

    await run_move(db, batch_size=10, sleep_ms=0, execute=True, drop_scalars=True)

    stored = await db.teams.find_one({"_id": "t0"})
    assert stored["bindings"] == [_GITHUB]
    assert not [name for name in SCALAR_FIELDS if name in stored]


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
    assert _published_filters() == [scalar_binding_filter()]
