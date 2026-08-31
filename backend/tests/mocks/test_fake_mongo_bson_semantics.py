"""Cross-type BSON behaviour of the Mongo attrappe, measured against the real server.

A column that mixes datetimes with strings is what an archive restore leaves behind, and an
attrappe that raises there reports a phantom regression instead of the production answer.
"""

from datetime import datetime, timezone

import pytest

from tests.mocks.fake_mongo import FakeDatabase

_EARLY = datetime(2026, 1, 1, tzinfo=timezone.utc)
_LATE = datetime(2026, 6, 1, tzinfo=timezone.utc)


async def _seed_mixed(db):
    await db.scans.insert_one({"_id": "text", "branch": "main", "created_at": "2026-03-01T00:00:00Z"})
    await db.scans.insert_one({"_id": "late", "branch": "main", "created_at": _LATE})
    await db.scans.insert_one({"_id": "early", "branch": "main", "created_at": _EARLY})
    await db.scans.insert_one({"_id": "undated", "branch": "main"})


@pytest.mark.asyncio
async def test_max_over_mixed_types_answers_with_the_date():
    db = FakeDatabase()
    await _seed_mixed(db)

    rows = await db.scans.aggregate(
        [{"$group": {"_id": "$branch", "newest": {"$max": "$created_at"}, "oldest": {"$min": "$created_at"}}}]
    ).to_list(None)

    assert rows[0]["newest"] == _LATE.replace(tzinfo=None)
    assert rows[0]["oldest"] == "2026-03-01T00:00:00Z"


@pytest.mark.asyncio
async def test_max_of_an_all_null_column_is_null():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "a", "branch": "main"})
    await db.scans.insert_one({"_id": "b", "branch": "main", "created_at": None})

    rows = await db.scans.aggregate([{"$group": {"_id": "$branch", "newest": {"$max": "$created_at"}}}]).to_list(None)

    assert rows[0]["newest"] is None


@pytest.mark.asyncio
async def test_cursor_sort_ranks_missing_before_string_before_date():
    db = FakeDatabase()
    await _seed_mixed(db)

    ascending = [doc["_id"] for doc in await db.scans.find({}, sort=[("created_at", 1)]).to_list(None)]

    assert ascending == ["undated", "text", "early", "late"]


@pytest.mark.asyncio
async def test_descending_cursor_sort_puts_the_missing_field_last():
    db = FakeDatabase()
    await _seed_mixed(db)

    descending = [doc["_id"] for doc in await db.scans.find({}, sort=[("created_at", -1)]).to_list(None)]

    assert descending == ["late", "early", "text", "undated"]


@pytest.mark.asyncio
async def test_sort_stage_ranks_the_same_way_as_the_cursor():
    db = FakeDatabase()
    await _seed_mixed(db)

    rows = await db.scans.aggregate([{"$sort": {"created_at": 1}}]).to_list(None)

    assert [row["_id"] for row in rows] == ["undated", "text", "early", "late"]


@pytest.mark.asyncio
async def test_find_one_with_a_sort_returns_the_newest_date_not_the_string():
    db = FakeDatabase()
    await _seed_mixed(db)

    newest = await db.scans.find_one({"branch": "main"}, sort=[("created_at", -1)])

    assert newest["_id"] == "late"


@pytest.mark.asyncio
async def test_a_date_bound_brackets_strings_and_missing_fields_out():
    db = FakeDatabase()
    await _seed_mixed(db)

    matched = {doc["_id"] for doc in await db.scans.find({"created_at": {"$gte": _EARLY}}).to_list(None)}

    assert matched == {"early", "late"}


@pytest.mark.asyncio
async def test_a_numeric_bound_does_not_match_a_boolean():
    db = FakeDatabase()
    await db.things.insert_one({"_id": "flag", "n": True})
    await db.things.insert_one({"_id": "number", "n": 4})

    matched = {doc["_id"] for doc in await db.things.find({"n": {"$gte": 1}}).to_list(None)}

    assert matched == {"number"}


@pytest.mark.asyncio
async def test_group_drops_a_key_the_document_does_not_carry():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "project_id": "p1"})

    rows = await db.scans.aggregate([{"$group": {"_id": {"p": "$project_id", "b": "$branch"}}}]).to_list(None)

    assert rows[0]["_id"] == {"p": "p1"}


@pytest.mark.asyncio
async def test_add_to_set_keeps_one_entry_per_distinct_value():
    db = FakeDatabase()
    for scan_id, commit in (("s1", "abc"), ("s2", "abc"), ("s3", "def")):
        await db.scans.insert_one({"_id": scan_id, "branch": "main", "commit_hash": commit})

    rows = await db.scans.aggregate(
        [
            {"$group": {"_id": "$branch", "commits": {"$addToSet": "$commit_hash"}}},
            {"$project": {"commit_count": {"$size": "$commits"}}},
        ]
    ).to_list(None)

    assert rows[0]["commit_count"] == 2


@pytest.mark.asyncio
async def test_size_of_a_non_array_fails_the_aggregation():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1"})

    with pytest.raises(TypeError, match=r"\$size requires an array"):
        await db.scans.aggregate([{"$project": {"n": {"$size": "$commits"}}}]).to_list(None)


@pytest.mark.asyncio
async def test_if_null_substitutes_for_both_a_null_and_a_missing_field():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "null", "commit_hash": None})
    await db.scans.insert_one({"_id": "missing"})

    rows = await db.scans.aggregate([{"$project": {"token": {"$ifNull": ["$commit_hash", "$_id"]}}}]).to_list(None)

    assert {row["token"] for row in rows} == {"null", "missing"}


@pytest.mark.asyncio
async def test_cond_reads_an_empty_string_as_true():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "branch": ""})

    rows = await db.scans.aggregate([{"$project": {"named": {"$cond": ["$branch", "yes", "no"]}}}]).to_list(None)

    assert rows[0]["named"] == "yes"


@pytest.mark.asyncio
async def test_cond_reads_a_missing_field_as_false():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1"})

    rows = await db.scans.aggregate([{"$project": {"named": {"$cond": ["$branch", "yes", "no"]}}}]).to_list(None)

    assert rows[0]["named"] == "no"


@pytest.mark.asyncio
async def test_comparison_expressions_rank_a_missing_field_below_a_number():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1"})

    rows = await db.scans.aggregate(
        [{"$project": {"below": {"$lt": ["$dep_count", 1]}, "above": {"$gte": ["$dep_count", 1]}}}]
    ).to_list(None)

    assert rows[0] == {"_id": "s1", "below": True, "above": False}


@pytest.mark.asyncio
async def test_eq_expression_keeps_booleans_apart_from_numbers():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "flag": True})

    rows = await db.scans.aggregate([{"$project": {"same": {"$eq": ["$flag", 1]}}}]).to_list(None)

    assert rows[0]["same"] is False


@pytest.mark.asyncio
async def test_ne_matches_a_document_that_omits_the_field():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "plain"})
    await db.scans.insert_one({"_id": "rescan", "is_rescan": True})

    matched = {doc["_id"] for doc in await db.scans.find({"is_rescan": {"$ne": True}}).to_list(None)}

    assert matched == {"plain"}


@pytest.mark.asyncio
async def test_in_with_null_matches_both_a_null_and_a_missing_field():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "null", "error": None})
    await db.scans.insert_one({"_id": "missing"})
    await db.scans.insert_one({"_id": "failed", "error": "boom"})

    matched = {doc["_id"] for doc in await db.scans.find({"error": {"$in": [None]}}).to_list(None)}

    assert matched == {"null", "missing"}
