"""An analytics request resolves the caller's projects with one read of the projects collection:
the scope read already carries what the scan resolution and the name map need."""

import pytest

from app.api.v1.helpers import analytics
from app.core.permissions import Permissions
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_the_scope_read_feeds_the_names_and_the_scans():
    db = FakeDatabase()
    for project_id in ("p-1", "p-2"):
        await db.projects.insert_one(
            {"_id": project_id, "name": f"name-{project_id}", "members": [{"user_id": "u-1", "role": "viewer"}]}
        )
    reads = 0
    find = db.projects.find

    def counting_find(*args, **kwargs):
        nonlocal reads
        reads += 1
        return find(*args, **kwargs)

    db.projects.find = counting_find
    user = User(id="u-1", username="u", email="u@corp.com", permissions=[Permissions.PROJECT_READ])

    projects = await analytics.get_user_projects(user, db)
    names, _ = await analytics.get_projects_with_scans(projects, db)

    assert names == {"p-1": "name-p-1", "p-2": "name-p-2"}
    assert reads == 1
