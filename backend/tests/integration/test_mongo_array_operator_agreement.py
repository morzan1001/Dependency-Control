"""Array operators on the attrappe and on a real server, pinned to what Percona Server for MongoDB 8.0.17-6 answers.

Project ownership is a ``team_ids`` array whose syncs must replace their own subset of owners, so
these operators carry the whole feature. A case the two backends answer differently fails on one of
them instead of drifting apart unnoticed.
"""

import pytest
from pymongo.errors import OperationFailure

from tests.helpers.databases import DATABASES
from tests.mocks.mongo_array_cases import (
    ADD_TO_SET_CASES,
    ARRAY_EXPRESSION_CASES,
    ARRAY_MATCH_CASES,
    CONFLICT_CASES,
    ELEM_MATCH_CASES,
    MEMBER_SOURCE_UPDATE_CASES,
    PIPELINE_UPDATE_CASES,
    PULL_CASES,
    TEAM_OWNERSHIP_CASES,
    UNWIND_CASES,
    run_agg_case,
    run_find_case,
    run_update_case,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize("database", DATABASES)]

_UPDATE_CASES = [
    *CONFLICT_CASES,
    *ADD_TO_SET_CASES,
    *PULL_CASES,
    *PIPELINE_UPDATE_CASES,
    *TEAM_OWNERSHIP_CASES,
    *MEMBER_SOURCE_UPDATE_CASES,
]
_FIND_CASES = [
    *ARRAY_MATCH_CASES,
    *ELEM_MATCH_CASES,
]
_AGG_CASES = [*UNWIND_CASES, *ARRAY_EXPRESSION_CASES]


@pytest.mark.parametrize("case", _UPDATE_CASES, ids=lambda c: c.name)
async def test_update_operator_matches_the_server(db, database, case):
    if case.error_code is not None:
        with pytest.raises(OperationFailure) as raised:
            await run_update_case(db.probe, case)
        assert raised.value.code == case.error_code
        return
    assert await run_update_case(db.probe, case) == case.expected


@pytest.mark.parametrize("case", _FIND_CASES, ids=lambda c: c.name)
async def test_query_operator_matches_the_server(db, database, case):
    if case.error_code is not None:
        with pytest.raises(OperationFailure) as raised:
            await run_find_case(db.probe, case)
        assert raised.value.code == case.error_code
        return
    assert await run_find_case(db.probe, case) == case.expected_ids


@pytest.mark.parametrize("case", _AGG_CASES, ids=lambda c: c.name)
async def test_aggregation_stage_matches_the_server(db, database, case):
    assert await run_agg_case(db.probe, case) == case.expected


async def test_a_conflicting_update_is_refused_even_when_nothing_matched(db, database):
    """The server parses the whole update before it looks for a document, so a filter that
    selects nothing still reports the conflict rather than reporting a clean no-op."""
    with pytest.raises(OperationFailure) as raised:
        await db.probe.update_one({"_id": "absent"}, {"$set": {"n": 1}, "$inc": {"n": 1}})

    assert raised.value.code == 40


async def test_replacing_one_syncs_owners_needs_two_writes(db, database):
    """What the multi-team sync has to do instead of one $pull + $addToSet: the conflict makes
    the combined form impossible, so the replacement runs as two updates."""
    await db.probe.insert_one({"_id": "p", "team_ids": ["gitlab-a", "manual-b"]})

    await db.probe.update_one({"_id": "p"}, {"$pull": {"team_ids": {"$in": ["gitlab-a"]}}})
    await db.probe.update_one({"_id": "p"}, {"$addToSet": {"team_ids": {"$each": ["gitlab-c"]}}})

    assert (await db.probe.find_one({"_id": "p"}))["team_ids"] == ["manual-b", "gitlab-c"]


async def test_a_pipeline_update_replaces_owners_in_one_write(db, database):
    await db.probe.insert_one({"_id": "p", "team_ids": ["gitlab-a", "manual-b"]})

    await db.probe.update_one(
        {"_id": "p"},
        [{"$set": {"team_ids": {"$setUnion": [{"$setDifference": ["$team_ids", ["gitlab-a"]]}, ["gitlab-c"]]}}}],
    )

    # Measured on the server: $setUnion answers in BSON order, not in the order it was fed.
    assert (await db.probe.find_one({"_id": "p"}))["team_ids"] == ["gitlab-c", "manual-b"]
