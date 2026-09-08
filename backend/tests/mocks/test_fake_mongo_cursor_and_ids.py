"""Cursor consumption, generated ids and write counts, measured against the real server.

Each of these reads the same in the attrappe and on the server only if the attrappe consumes
what it hands out: a paging loop that never terminates, an id the driver stamped that is not
there, or an upsert count that is a mock, all turn a green test into a claim about nothing.
"""

import pytest
from pymongo import UpdateOne

from tests.mocks.fake_mongo import FakeDatabase

_PAGE = 2
_TOTAL = 5
_PAGES_OF_FIVE_BY_TWO = [[0, 1], [2, 3], [4], []]
_NOTHING_LEFT = 0
_ONE_MATCH = 1
_ONE_UPSERT = 1
_NO_UPSERT = 0


async def _seed_numbers(db, count: int = _TOTAL) -> None:
    await db.scans.insert_many([{"_id": index, "n": index} for index in range(count)])


@pytest.mark.asyncio
async def test_to_list_pages_through_the_cursor_and_then_empties():
    db = FakeDatabase()
    await _seed_numbers(db)
    cursor = db.scans.find({})

    pages = [[doc["n"] for doc in await cursor.to_list(length=_PAGE)] for _ in range(len(_PAGES_OF_FIVE_BY_TWO))]

    assert pages == _PAGES_OF_FIVE_BY_TWO


@pytest.mark.asyncio
async def test_an_aggregate_cursor_pages_the_same_way():
    db = FakeDatabase()
    await _seed_numbers(db)
    cursor = db.scans.aggregate([{"$sort": {"n": 1}}])

    pages = [[doc["n"] for doc in await cursor.to_list(length=_PAGE)] for _ in range(len(_PAGES_OF_FIVE_BY_TWO))]

    assert pages == _PAGES_OF_FIVE_BY_TWO


@pytest.mark.asyncio
async def test_a_drained_cursor_yields_nothing_more():
    db = FakeDatabase()
    await _seed_numbers(db)
    cursor = db.scans.find({})
    await cursor.to_list(length=None)

    leftovers = [doc async for doc in cursor]

    assert len(leftovers) == _NOTHING_LEFT


@pytest.mark.asyncio
async def test_insert_one_stamps_the_id_on_the_callers_document():
    db = FakeDatabase()
    entry = {"webhook_id": "w1", "success": True}

    result = await db.webhook_deliveries.insert_one(entry)

    assert entry["_id"] == result.inserted_id


@pytest.mark.asyncio
async def test_a_generated_id_never_reuses_a_deleted_one():
    db = FakeDatabase()
    for n in range(3):
        await db.scans.insert_one({"n": n})
    await db.scans.delete_one({"n": 0})

    await db.scans.insert_one({"n": 99})

    remaining = await db.scans.find({}).to_list(length=None)
    assert sorted(doc["n"] for doc in remaining) == [1, 2, 99]


@pytest.mark.asyncio
async def test_bulk_write_reports_matched_modified_and_upserted():
    db = FakeDatabase()
    await db.findings.insert_many([{"_id": "a", "n": 1}])

    result = await db.findings.bulk_write(
        [
            UpdateOne({"_id": "a"}, {"$set": {"n": 10}}),
            UpdateOne({"_id": "b"}, {"$set": {"n": 20}}, upsert=True),
        ]
    )

    assert (result.matched_count, result.modified_count, result.upserted_count) == (
        _ONE_MATCH,
        _ONE_MATCH,
        _ONE_UPSERT,
    )


@pytest.mark.asyncio
async def test_bulk_write_does_not_count_an_update_that_changed_nothing():
    db = FakeDatabase()
    await db.findings.insert_many([{"_id": "a", "n": 1}])

    result = await db.findings.bulk_write([UpdateOne({"_id": "a"}, {"$set": {"n": 1}})])

    assert (result.matched_count, result.modified_count, result.upserted_count) == (
        _ONE_MATCH,
        _NOTHING_LEFT,
        _NO_UPSERT,
    )
