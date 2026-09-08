"""ProjectRepository's GitLab multi-instance lookups, driven through FakeDatabase."""

import pytest

from app.repositories.projects import ProjectRepository
from tests.mocks.fake_mongo import FakeDatabase

_INSTANCE_A = "instance-a"
_INSTANCE_B = "instance-b"
_GITLAB_PROJECT_ID = 12345
_INSTANCE_A_PROJECTS = 3


def _project_doc(project_id, instance_id, gitlab_project_id):
    return {
        "_id": project_id,
        "name": project_id,
        "owner_id": "u1",
        "gitlab_instance_id": instance_id,
        "gitlab_project_id": gitlab_project_id,
    }


@pytest.fixture
def db():
    database = FakeDatabase()
    for index in range(_INSTANCE_A_PROJECTS):
        database.projects._docs[f"a-{index}"] = _project_doc(f"a-{index}", _INSTANCE_A, _GITLAB_PROJECT_ID + index)
    # Same numeric project id on a second instance: the composite key is what tells them apart.
    database.projects._docs["b-0"] = _project_doc("b-0", _INSTANCE_B, _GITLAB_PROJECT_ID)
    return database


class TestCompositeKeyLookup:
    @pytest.mark.asyncio
    async def test_the_instance_id_decides_between_two_rows_sharing_a_gitlab_project_id(self, db):
        repo = ProjectRepository(db)

        found = await repo.get_by_gitlab_composite_key(_INSTANCE_B, _GITLAB_PROJECT_ID)

        assert found is not None
        assert found.id == "b-0"

    @pytest.mark.asyncio
    async def test_an_unknown_pair_resolves_to_nothing(self, db):
        repo = ProjectRepository(db)

        assert await repo.get_by_gitlab_composite_key(_INSTANCE_A, 99999) is None
        assert await repo.get_raw_by_gitlab_composite_key("absent", _GITLAB_PROJECT_ID) is None

    @pytest.mark.asyncio
    async def test_the_raw_lookup_returns_the_stored_document(self, db):
        repo = ProjectRepository(db)

        raw = await repo.get_raw_by_gitlab_composite_key(_INSTANCE_A, _GITLAB_PROJECT_ID)

        assert raw == _project_doc("a-0", _INSTANCE_A, _GITLAB_PROJECT_ID)


class TestInstanceQueries:
    @pytest.mark.asyncio
    async def test_list_by_instance_returns_that_instance_only(self, db):
        repo = ProjectRepository(db)

        listed = await repo.list_by_instance(_INSTANCE_A)

        assert [project.id for project in listed] == [f"a-{i}" for i in range(_INSTANCE_A_PROJECTS)]

    @pytest.mark.asyncio
    async def test_list_by_instance_pages_from_the_requested_offset(self, db):
        repo = ProjectRepository(db)

        page = await repo.list_by_instance(_INSTANCE_A, skip=1, limit=1)

        assert [project.id for project in page] == ["a-1"]

    @pytest.mark.asyncio
    async def test_count_by_instance_counts_that_instance_only(self, db):
        repo = ProjectRepository(db)

        assert await repo.count_by_instance(_INSTANCE_A) == _INSTANCE_A_PROJECTS
        assert await repo.count_by_instance(_INSTANCE_B) == 1
