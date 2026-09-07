"""Cross-type BSON behaviour of the Mongo attrappe, measured against the real server.

A column that mixes datetimes with strings is what an archive restore leaves behind, and an
attrappe that raises there reports a phantom regression instead of the production answer.
"""

from datetime import datetime, timezone

import pytest

from tests.mocks.fake_mongo import FakeDatabase

_EARLY = datetime(2026, 1, 1, tzinfo=timezone.utc)
_LATE = datetime(2026, 6, 1, tzinfo=timezone.utc)
_INTEGER_TRUE = 1
_SUB_MILLISECOND = datetime(2026, 3, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
_SAME_MILLISECOND = datetime(2026, 3, 1, 12, 0, 0, 123999, tzinfo=timezone.utc)
_TRUNCATED_MICROSECONDS = 123000
_INVALID_SORT_DIRECTION = 2


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
async def test_ne_against_an_array_compares_the_whole_array_as_well_as_its_elements():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "empty", "refs": []})
    await db.scans.insert_one({"_id": "filled", "refs": [{"gridfs_id": "g1"}]})

    without_empty = {doc["_id"] for doc in await db.scans.find({"refs": {"$ne": []}}).to_list(None)}
    without_filled = {doc["_id"] for doc in await db.scans.find({"refs": {"$ne": [{"gridfs_id": "g1"}]}}).to_list(None)}

    assert without_empty == {"filled"}
    assert without_filled == {"empty"}


@pytest.mark.asyncio
async def test_in_with_null_matches_both_a_null_and_a_missing_field():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "null", "error": None})
    await db.scans.insert_one({"_id": "missing"})
    await db.scans.insert_one({"_id": "failed", "error": "boom"})

    matched = {doc["_id"] for doc in await db.scans.find({"error": {"$in": [None]}}).to_list(None)}

    assert matched == {"null", "missing"}


@pytest.mark.asyncio
async def test_ne_true_keeps_a_document_whose_flag_is_the_integer_one():
    """Python calls 1 and True equal; BSON int32 and bool are different types, and the server
    selects the integer-flagged document — which on the retention cursor means deleting it."""
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "int-flag", "is_release": _INTEGER_TRUE})
    await db.scans.insert_one({"_id": "bool-flag", "is_release": True})

    selected = {doc["_id"] for doc in await db.scans.find({"is_release": {"$ne": True}}).to_list(None)}

    assert selected == {"int-flag"}


@pytest.mark.asyncio
async def test_nin_naming_both_spellings_excludes_both():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "int-flag", "is_release": _INTEGER_TRUE})
    await db.scans.insert_one({"_id": "bool-flag", "is_release": True})
    await db.scans.insert_one({"_id": "unflagged"})

    selected = {doc["_id"] for doc in await db.scans.find({"is_release": {"$nin": [True, 1]}}).to_list(None)}

    assert selected == {"unflagged"}


@pytest.mark.asyncio
async def test_equality_on_a_boolean_does_not_match_the_integer_one():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "int-flag", "is_release": _INTEGER_TRUE})
    await db.scans.insert_one({"_id": "bool-flag", "is_release": True})

    selected = {doc["_id"] for doc in await db.scans.find({"is_release": True}).to_list(None)}

    assert selected == {"bool-flag"}


@pytest.mark.asyncio
async def test_a_stored_datetime_loses_its_sub_millisecond_digits():
    """Dates go on the wire as int64 milliseconds, so a test seeding two instants from two clock
    reads gets a total order here and a coin flip in production."""
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "created_at": _SUB_MILLISECOND})
    await db.scans.insert_one({"_id": "s2", "created_at": _SAME_MILLISECOND})

    stored = {doc["_id"]: doc["created_at"] for doc in await db.scans.find({}).to_list(None)}

    assert stored["s1"] == _SUB_MILLISECOND.replace(tzinfo=None, microsecond=_TRUNCATED_MICROSECONDS)
    assert stored["s1"] == stored["s2"]


@pytest.mark.asyncio
async def test_a_query_bound_is_truncated_the_way_the_stored_value_was():
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "created_at": _SUB_MILLISECOND})

    matched = {doc["_id"] for doc in await db.scans.find({"created_at": {"$gt": _SAME_MILLISECOND}}).to_list(None)}

    assert matched == set()


@pytest.mark.asyncio
async def test_setting_a_boolean_over_the_integer_counts_as_a_modification():
    """The server compares BSON types, so 1 -> true is a write; Python's == would call it a no-op."""
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "is_release": _INTEGER_TRUE})

    result = await db.scans.update_one({"_id": "s1"}, {"$set": {"is_release": True}})

    assert result.modified_count == 1
    assert result.matched_count == 1


@pytest.mark.asyncio
async def test_update_one_reports_a_filter_miss_and_a_no_op_apart():
    """A conditional write reads matched_count: 0 means the guard refused, 1 means nothing changed."""
    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "is_release": True})

    missed = await db.scans.update_one({"_id": "s1", "is_release": False}, {"$set": {"is_release": True}})
    no_op = await db.scans.update_one({"_id": "s1"}, {"$set": {"is_release": True}})

    assert (missed.matched_count, missed.modified_count) == (0, 0)
    assert (no_op.matched_count, no_op.modified_count) == (1, 0)


@pytest.mark.asyncio
async def test_a_sort_direction_the_server_rejects_is_rejected_here_too():
    """A typo in a sort spec must not read as ascending; the server refuses the whole aggregation."""
    from pymongo.errors import OperationFailure

    db = FakeDatabase()
    await db.scans.insert_one({"_id": "s1", "created_at": _EARLY})

    with pytest.raises(OperationFailure):
        await db.scans.aggregate([{"$sort": {"created_at": _INVALID_SORT_DIRECTION}}]).to_list(None)
