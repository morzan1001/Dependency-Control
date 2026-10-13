"""A second project for one GitLab project is refused, whatever numeric type a writer stored its id in."""

import pytest
from bson.int64 import Int64
from pymongo.errors import DuplicateKeyError

from app.core.init_db import create_indexes


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("stored_as", [Int64, float], ids=["int64", "double"])
async def test_a_second_project_for_one_gitlab_project_is_refused(db, stored_as):
    await create_indexes(db)
    await db.projects.insert_one({"_id": "p1", "gitlab_instance_id": "gl-1", "gitlab_project_id": 4711})

    with pytest.raises(DuplicateKeyError):
        await db.projects.insert_one({"_id": "p2", "gitlab_instance_id": "gl-1", "gitlab_project_id": stored_as(4711)})
