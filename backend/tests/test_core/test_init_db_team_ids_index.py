import pytest

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_projects_are_indexed_on_team_ids():
    """Every team-scoped query filters on team_ids, so without the index each one scans the collection."""
    db = FakeDatabase()

    await create_indexes(db)

    assert "team_ids" in db.projects.created_indexes
