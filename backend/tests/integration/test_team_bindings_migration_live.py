"""The deploy order, measured: expand, roll, contract — against a real server and the real index.

Each step of the runbook makes a claim about what one of the two images can still read. The claims
are what this file executes, because an order that leaves either image reading nothing costs the
estate its team ownership for the length of the rollout.
"""

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB
from app.core.init_db import create_team_indexes
from app.repositories.teams import TeamRepository
from scripts.backfill_team_bindings import (
    EXIT_SCALAR_BINDINGS_FOUND,
    SCALAR_FIELDS,
    count_scalar_bindings,
    run_move,
    run_verify,
)

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

# Two teams as the previous image left them: every field present, unset ones explicitly null.
_UNMIGRATED = [
    {
        "_id": "t-payments",
        "name": "Payments Guild",
        "members": [],
        **dict.fromkeys(SCALAR_FIELDS),
        "github_instance_id": "gh-1",
        "github_org": "acme",
        "github_team_id": 4711,
        "github_team_slug": "payments",
    },
    {
        "_id": "t-edge",
        "name": "GitLab Group: mo/edge",
        "members": [],
        **dict.fromkeys(SCALAR_FIELDS),
        "gitlab_instance_id": "gl-1",
        "gitlab_group_id": 77,
        "gitlab_group_path": "mo/edge",
    },
    {"_id": "t-manual", "name": "Atlas", "members": [], **dict.fromkeys(SCALAR_FIELDS)},
]


async def _seed(db) -> TeamRepository:
    await create_team_indexes(db)
    for team in _UNMIGRATED:
        await db.teams.insert_one(dict(team))
    return TeamRepository(db)


async def test_the_new_image_reads_nothing_on_an_unmigrated_team(db):
    """The measurement the order rests on. Rolling the image first would leave every ingest
    resolving no team, and the ownership write then retires the real one."""
    repo = await _seed(db)

    assert await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 4711) is None
    assert await repo.find_raw_by_github_org("gh-1", "acme") == []
    # And to the new image every one of them looks free to adopt, including the bound ones.
    assert len(await repo.find_raw_unbound_for_instance("gh-1")) == 3


async def test_after_the_expand_pass_both_shapes_answer(db):
    """The rolling update serves old and new pods together, so both reads have to work at once."""
    repo = await _seed(db)

    planned, matched = await run_move(db, batch_size=10, sleep_ms=0, execute=True, drop_scalars=False)

    assert (planned, matched) == (2, 2)
    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 4711))["_id"] == "t-payments"
    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITLAB, "gl-1", 77))["_id"] == "t-edge"
    # What the previous image reads is untouched, field for field.
    for team in _UNMIGRATED:
        stored = await db.teams.find_one({"_id": team["_id"]})
        assert {name: stored.get(name) for name in SCALAR_FIELDS} == {
            name: team[name] for name in SCALAR_FIELDS
        }
    assert await run_verify(db) == EXIT_SCALAR_BINDINGS_FOUND


async def test_the_contract_pass_sheds_every_scalar_and_releases_the_gate(db):
    repo = await _seed(db)
    await run_move(db, batch_size=10, sleep_ms=0, execute=True, drop_scalars=False)

    planned, matched = await run_move(db, batch_size=10, sleep_ms=0, execute=True, drop_scalars=True)

    assert (planned, matched) == (3, 3)
    assert await count_scalar_bindings(db) == 0
    assert await run_verify(db) == 0
    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 4711))["_id"] == "t-payments"
    assert [team["_id"] for team in await repo.find_raw_unbound_for_instance("gh-1")] == ["t-edge", "t-manual"]


async def test_a_binding_an_old_pod_wrote_during_the_rollout_is_carried_over(db):
    """The window the two passes exist for: a pod on the previous image adopts a team into the
    scalars after the expand pass has already been over it."""
    repo = await _seed(db)
    await run_move(db, batch_size=10, sleep_ms=0, execute=True, drop_scalars=False)
    await db.teams.update_one(
        {"_id": "t-manual"},
        {"$set": {"github_instance_id": "gh-1", "github_org": "acme", "github_team_id": 900,
                  "github_team_slug": "cards"}},
    )

    await run_move(db, batch_size=10, sleep_ms=0, execute=True, drop_scalars=True)

    assert (await repo.get_raw_by_binding(TEAM_SOURCE_GITHUB, "gh-1", 900))["_id"] == "t-manual"
    assert await count_scalar_bindings(db) == 0


async def test_the_migration_cannot_hand_one_group_to_two_teams(db):
    """The scalar indexes kept the estate free of duplicates, and the new index is what proves the
    derived entries inherited that."""
    await _seed(db)
    await db.teams.insert_one(
        {"_id": "t-rival", "name": "Rival", "members": [], **dict.fromkeys(SCALAR_FIELDS),
         "github_instance_id": "gh-1", "github_org": "acme", "github_team_id": 4711}
    )

    with pytest.raises(Exception, match="E11000"):
        await run_move(db, batch_size=10, sleep_ms=0, execute=True, drop_scalars=False)
