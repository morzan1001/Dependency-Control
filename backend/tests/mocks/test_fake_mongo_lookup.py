"""The in-memory $lookup has to match real MongoDB for array localFields."""

import pytest

from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_lookup_on_an_array_local_field_joins_every_element():
    """Real MongoDB treats an array localField as a membership test, not an equality test."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "Alpha"})
    await db.teams.insert_one({"_id": "t2", "name": "Bravo"})
    await db.teams.insert_one({"_id": "t3", "name": "Unrelated"})
    await db.projects.insert_one({"_id": "p1", "team_ids": ["t1", "t2"]})

    result = await db.projects.aggregate(
        [{"$lookup": {"from": "teams", "localField": "team_ids", "foreignField": "_id", "as": "team_data"}}]
    ).to_list(length=None)

    assert [team["name"] for team in result[0]["team_data"]] == ["Alpha", "Bravo"]


@pytest.mark.asyncio
async def test_lookup_on_a_scalar_local_field_is_unchanged():
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "Alpha"})
    await db.projects.insert_one({"_id": "p1", "team_id": "t1"})

    result = await db.projects.aggregate(
        [{"$lookup": {"from": "teams", "localField": "team_id", "foreignField": "_id", "as": "team_data"}}]
    ).to_list(length=None)

    assert [team["name"] for team in result[0]["team_data"]] == ["Alpha"]


@pytest.mark.asyncio
async def test_lookup_on_an_empty_array_joins_nothing():
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "Alpha"})
    await db.projects.insert_one({"_id": "p1", "team_ids": []})

    result = await db.projects.aggregate(
        [{"$lookup": {"from": "teams", "localField": "team_ids", "foreignField": "_id", "as": "team_data"}}]
    ).to_list(length=None)

    assert result[0]["team_data"] == []
