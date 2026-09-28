"""The id-to-name map names existing projects only; an empty or unknown id is the caller's to label."""

import pytest

from app.repositories.projects import ProjectRepository
from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_names_come_back_for_existing_projects_only():
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "p1", "name": "Alpha"})
    await db.projects.insert_one({"_id": "p2", "name": "Beta"})

    names = await ProjectRepository(db).names_by_ids(["p1", "p1", "", None, "gone"])

    assert names == {"p1": "Alpha"}


@pytest.mark.asyncio
async def test_no_ids_answer_an_empty_map():
    assert await ProjectRepository(FakeDatabase()).names_by_ids([]) == {}
