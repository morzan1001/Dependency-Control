"""Projection fidelity of the Mongo attrappe: a wrong trim would validate wrong production reads."""

import pytest

from tests.mocks.fake_mongo import FakeDatabase, _apply_projection


def test_sibling_paths_over_one_array_project_into_the_same_elements():
    doc = {"_id": "x", "a": [{"b": 1, "c": 2, "d": 3}, {"b": 4, "c": 5, "d": 6}]}

    assert _apply_projection(doc, {"a.b": 1, "a.c": 1}) == {"_id": "x", "a": [{"b": 1, "c": 2}, {"b": 4, "c": 5}]}


def test_array_element_without_the_projected_field_stays_as_an_empty_document():
    doc = {"_id": "x", "a": [{"b": 1}, {"c": 2}]}

    assert _apply_projection(doc, {"a.b": 1}) == {"_id": "x", "a": [{"b": 1}, {}]}


def test_scalar_array_elements_are_dropped_when_a_subfield_is_projected():
    doc = {"_id": "x", "a": [7, {"b": 1}]}

    assert _apply_projection(doc, {"a.b": 1}) == {"_id": "x", "a": [{"b": 1}]}


def test_empty_array_survives_as_an_empty_array():
    doc = {"_id": "x", "a": []}

    assert _apply_projection(doc, {"a.b": 1}) == {"_id": "x", "a": []}


def test_missing_leaf_keeps_the_existing_parent_as_an_empty_document():
    doc = {"_id": "x", "a": {"z": 1}}

    assert _apply_projection(doc, {"a.b": 1}) == {"_id": "x", "a": {}}


def test_projection_does_not_alias_the_stored_document():
    doc = {"_id": "x", "a": [{"b": [1, 2]}]}

    projected = _apply_projection(doc, {"a.b": 1})
    projected["a"][0]["b"].append(3)

    assert doc["a"][0]["b"] == [1, 2]


@pytest.mark.asyncio
async def test_find_applies_the_same_trim_as_find_one():
    db = FakeDatabase()
    await db.things.insert_one({"_id": "x", "a": [{"b": 1, "c": 2}], "other": "dropped"})

    from_find = (await db.things.find({}, {"a.b": 1, "a.c": 1}).to_list(1))[0]

    assert from_find == await db.things.find_one({"_id": "x"}, {"a.b": 1, "a.c": 1})
    assert from_find == {"_id": "x", "a": [{"b": 1, "c": 2}]}
