import pytest

from app.models.project import Project
from app.repositories.projects import ProjectRepository
from tests.mocks.fake_mongo import FakeDatabase

_GITLAB_PROJECT_ID = 12345


def _key(instance_id: str) -> dict:
    return {"gitlab_instance_id": instance_id, "gitlab_project_id": _GITLAB_PROJECT_ID}


@pytest.fixture
def db():
    database = FakeDatabase()
    database.projects._docs["a-0"] = {"_id": "a-0", "name": "a-0", **_key("instance-a")}
    return database


class TestFindOrCreateByKey:
    @pytest.mark.asyncio
    async def test_the_project_holding_the_key_is_returned_untouched(self, db):
        project, created = await ProjectRepository(db).find_or_create_by_key(
            _key("instance-a"), Project(name="new", **_key("instance-a"))
        )

        assert (project.id, project.name, created) == ("a-0", "a-0", False)

    @pytest.mark.asyncio
    async def test_the_same_project_id_on_another_instance_is_another_project(self, db):
        new = Project(name="b-0", **_key("instance-b"))

        project, created = await ProjectRepository(db).find_or_create_by_key(_key("instance-b"), new)

        assert (project.id, created) == (new.id, True)
        assert (await ProjectRepository(db).find_one_raw(_key("instance-a")))["_id"] == "a-0"
