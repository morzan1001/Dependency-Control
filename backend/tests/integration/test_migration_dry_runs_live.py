"""A dry run of each team migration reports its plan and leaves the database exactly as it was.

Operators ran these dry runs against production and read the plan before authorising the write, so
the claim is about the server rather than about a counter the script keeps: every document of every
collection, field for field and in the order the server stores them. A dry run that quietly wrote
would be found only by its consequences.

Each case then executes the same pass, so the comparison is never satisfied by a corpus the
migration had nothing to do with.
"""

from collections.abc import Awaitable, Callable
from typing import Any

import bson
import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB
from scripts.backfill_team_bindings import SCALAR_FIELDS
from scripts.backfill_team_bindings import run_move as run_bindings
from scripts.backfill_team_member_sources import run_stamp as run_member_sources
from scripts.backfill_team_source_instances import run_stamp as run_source_instances

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_GITLAB_INSTANCE = "gl-prod"
_GITHUB_INSTANCE = "gh-cloud"

_Pass = Callable[[Any, bool], Awaitable[int]]


async def _seed_bindings(db) -> None:
    await db.teams.insert_many(
        [
            {
                "_id": "t-payments",
                "name": "Payments Guild",
                "members": [],
                **dict.fromkeys(SCALAR_FIELDS),
                "github_instance_id": _GITHUB_INSTANCE,
                "github_org": "acme",
                "github_team_id": 4711,
                "github_team_slug": "payments",
            },
            {
                "_id": "t-edge",
                "name": "GitLab Group: mo/edge",
                "members": [],
                **dict.fromkeys(SCALAR_FIELDS),
                "gitlab_instance_id": _GITLAB_INSTANCE,
                "gitlab_group_id": 77,
                "gitlab_group_path": "mo/edge",
            },
            {"_id": "t-manual", "name": "Atlas", "members": [], **dict.fromkeys(SCALAR_FIELDS)},
        ]
    )


async def _seed_instances(db) -> None:
    await db.gitlab_instances.insert_one({"_id": _GITLAB_INSTANCE, "sync_teams": True})
    await db.github_instances.insert_one({"_id": _GITHUB_INSTANCE, "sync_teams": True})


async def _seed_source_instances(db) -> None:
    await _seed_instances(db)
    await db.projects.insert_many(
        [
            {
                "_id": "p-edge",
                "name": "edge",
                "team_sources": {"t-edge": TEAM_SOURCE_GITLAB, "t-atlas": "manual"},
                "team_source": TEAM_SOURCE_GITLAB,
            },
            {"_id": "p-pay", "name": "pay", "team_sources": {"t-payments": TEAM_SOURCE_GITHUB}},
            {"_id": "p-manual", "name": "manual", "team_sources": {"t-atlas": "manual"}},
        ]
    )


async def _seed_member_sources(db) -> None:
    await _seed_instances(db)
    await db.teams.insert_many(
        [
            {
                "_id": "t-edge",
                "name": "GitLab Group: mo/edge",
                "members": [
                    {"user_id": "u-ada", "role": "admin", "source": TEAM_SOURCE_GITLAB},
                    {"user_id": "u-eve", "role": "member", "source": "manual"},
                ],
            },
            {
                "_id": "t-payments",
                "name": "Payments Guild",
                "members": [{"user_id": "u-bob", "role": "member", "source": TEAM_SOURCE_GITHUB}],
            },
        ]
    )


async def _bindings_expand(db, execute: bool) -> int:
    planned, _matched = await run_bindings(db, batch_size=10, sleep_ms=0, execute=execute, drop_scalars=False)
    return planned


async def _bindings_contract(db, execute: bool) -> int:
    planned, _matched = await run_bindings(db, batch_size=10, sleep_ms=0, execute=execute, drop_scalars=True)
    return planned


async def _source_instances(db, execute: bool) -> int:
    planned, _matched = await run_source_instances(db, batch_size=10, sleep_ms=0, execute=execute)
    return planned


async def _member_sources(db, execute: bool) -> int:
    return (await run_member_sources(db, batch_size=10, sleep_ms=0, execute=execute)).teams_planned


_PASSES: list[tuple[str, Callable[[Any], Awaitable[None]], _Pass]] = [
    ("backfill_team_bindings", _seed_bindings, _bindings_expand),
    ("backfill_team_bindings --drop-scalars", _seed_bindings, _bindings_contract),
    ("backfill_team_source_instances", _seed_source_instances, _source_instances),
    ("backfill_team_member_sources", _seed_member_sources, _member_sources),
]


async def _snapshot(db) -> dict[str, list[bytes]]:
    """Every document of every collection as the server encodes it.

    BSON rather than dicts: a rewrite that only reorders a document's fields is still a write, and
    dict equality would call it no change.
    """
    return {
        name: [bson.encode(doc) for doc in await db[name].find({}).sort("_id", 1).to_list(None)]
        for name in sorted(await db.list_collection_names())
    }


@pytest.mark.parametrize(("command", "seed", "run_pass"), _PASSES, ids=[case[0] for case in _PASSES])
async def test_a_dry_run_plans_the_write_and_makes_none(db, command, seed, run_pass, capsys):
    await seed(db)
    before = await _snapshot(db)

    planned = await run_pass(db, False)
    reported = capsys.readouterr().out

    assert planned, f"{command} planned nothing, so the dry run had no write to withhold"
    assert await _snapshot(db) == before
    # The operator reads the plan off the progress line, and the withheld matched count is what
    # tells them the documents were only counted.
    assert f"planned={planned}" in reported
    assert "matched=N/A" in reported

    assert await run_pass(db, True) == planned
    assert await _snapshot(db) != before
