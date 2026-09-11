"""The same array-operator table as ``tests/mocks/test_fake_mongo_array_operators.py``, run
against a real MongoDB.

Both sides assert the identical expectations, so the pair is what keeps the attrappe honest: a
case the two answer differently fails here or there instead of drifting apart unnoticed.
"""

import pytest
from pymongo.errors import OperationFailure

from tests.mocks.mongo_array_cases import (
    ADD_TO_SET_CASES,
    ARRAY_EXPRESSION_CASES,
    ARRAY_MATCH_CASES,
    CONFLICT_CASES,
    ELEM_MATCH_CASES,
    PIPELINE_UPDATE_CASES,
    PULL_CASES,
    UNWIND_CASES,
    run_agg_case,
    run_find_case,
    run_update_case,
)

_UPDATE_CASES = [*CONFLICT_CASES, *ADD_TO_SET_CASES, *PULL_CASES, *PIPELINE_UPDATE_CASES]
_FIND_CASES = [*ARRAY_MATCH_CASES, *ELEM_MATCH_CASES]
_AGG_CASES = [*UNWIND_CASES, *ARRAY_EXPRESSION_CASES]


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("case", _UPDATE_CASES, ids=lambda c: c.name)
async def test_update_operator_on_a_real_server(db, case):
    collection = db["probe"]
    if case.error_code is not None:
        with pytest.raises(OperationFailure) as raised:
            await run_update_case(collection, case)
        assert raised.value.code == case.error_code
        return
    assert await run_update_case(collection, case) == case.expected


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("case", _FIND_CASES, ids=lambda c: c.name)
async def test_query_operator_on_a_real_server(db, case):
    collection = db["probe"]
    if case.error_code is not None:
        with pytest.raises(OperationFailure) as raised:
            await run_find_case(collection, case)
        assert raised.value.code == case.error_code
        return
    assert await run_find_case(collection, case) == case.expected_ids


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("case", _AGG_CASES, ids=lambda c: c.name)
async def test_aggregation_stage_on_a_real_server(db, case):
    assert await run_agg_case(db["probe"], case) == case.expected
