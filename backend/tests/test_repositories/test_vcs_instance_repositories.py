"""VcsInstanceRepository behaviour, driven through FakeDatabase.

Asserting on the query document instead punishes correctness: rewriting exists_by_* as
count_documents(query, limit=1) reddens ten call-shape tests while a dropped .skip() and an
access token that never reaches Mongo both stay green.
"""

import pytest

from app.models.github_instance import GitHubInstance
from app.models.gitlab_instance import GitLabInstance
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from tests.mocks.fake_mongo import FakeDatabase

_CREATED_BY = "admin"
_TOKEN = "glpat-secret"
_BASE_URL = "https://vcs.example.com"
_ACTIVE_COUNT = 3

_REPOSITORIES = [
    pytest.param(GitLabInstanceRepository, GitLabInstance, "gitlab_instances", id="gitlab"),
    pytest.param(GitHubInstanceRepository, GitHubInstance, "github_instances", id="github"),
]


def _instance(model, instance_id="i-1", name="Primary", url=_BASE_URL, **overrides):
    return model(id=instance_id, name=name, url=url, created_by=_CREATED_BY, **overrides)


@pytest.mark.parametrize(("repo_class", "model", "collection_name"), _REPOSITORIES)
class TestSharedVcsInstanceBehaviour:
    @pytest.mark.asyncio
    async def test_writes_land_in_the_collection_the_repository_declares(self, repo_class, model, collection_name):
        db = FakeDatabase()

        await repo_class(db).create(_instance(model))

        assert await db[collection_name].find_one({"_id": "i-1"}) is not None

    @pytest.mark.asyncio
    async def test_a_lookup_url_is_matched_with_its_trailing_slash_stripped(
        self, repo_class, model, collection_name
    ):
        db = FakeDatabase()
        repo = repo_class(db)
        await repo.create(_instance(model))

        found = await repo.get_by_url(f"{_BASE_URL}/")

        assert found is not None
        assert found.id == "i-1"
        assert await repo.exists_by_url(f"{_BASE_URL}/") is True

    @pytest.mark.asyncio
    async def test_the_access_token_reaches_mongo_despite_being_excluded_from_the_model_dump(
        self, repo_class, model, collection_name
    ):
        db = FakeDatabase()
        repo = repo_class(db)

        await repo.create(_instance(model, access_token=_TOKEN))

        assert (await db[collection_name].find_one({"_id": "i-1"}))["access_token"] == _TOKEN
        assert (await repo.get_by_id("i-1")).access_token == _TOKEN

    @pytest.mark.asyncio
    async def test_list_active_pages_through_the_active_rows_only(self, repo_class, model, collection_name):
        db = FakeDatabase()
        repo = repo_class(db)
        for index in range(_ACTIVE_COUNT):
            await repo.create(_instance(model, instance_id=f"a-{index}", name=f"Active {index}"))
        await repo.create(_instance(model, instance_id="inactive", name="Inactive", is_active=False))

        page = await repo.list_active(skip=1, limit=1)

        assert [instance.id for instance in page] == ["a-1"]
        assert [instance.id for instance in await repo.list_active()] == [f"a-{i}" for i in range(_ACTIVE_COUNT)]
        assert await repo.count_active() == _ACTIVE_COUNT
        assert await repo.count_all() == _ACTIVE_COUNT + 1

    @pytest.mark.asyncio
    async def test_list_all_pages_through_every_row(self, repo_class, model, collection_name):
        db = FakeDatabase()
        repo = repo_class(db)
        await repo.create(_instance(model, instance_id="a-0", name="Active"))
        await repo.create(_instance(model, instance_id="inactive", name="Inactive", is_active=False))

        assert [instance.id for instance in await repo.list_all()] == ["a-0", "inactive"]
        assert [instance.id for instance in await repo.list_all(skip=1, limit=1)] == ["inactive"]

    @pytest.mark.asyncio
    async def test_a_name_is_taken_unless_the_row_holding_it_is_the_excluded_one(
        self, repo_class, model, collection_name
    ):
        db = FakeDatabase()
        repo = repo_class(db)
        await repo.create(_instance(model, name="Primary"))

        assert await repo.exists_by_name("Primary") is True
        assert await repo.exists_by_name("Primary", exclude_id="i-1") is False
        assert await repo.exists_by_name("Primary", exclude_id="other") is True
        assert await repo.exists_by_name("Absent") is False

    @pytest.mark.asyncio
    async def test_a_url_is_taken_unless_the_row_holding_it_is_the_excluded_one(
        self, repo_class, model, collection_name
    ):
        db = FakeDatabase()
        repo = repo_class(db)
        await repo.create(_instance(model))

        assert await repo.exists_by_url(_BASE_URL) is True
        assert await repo.exists_by_url(_BASE_URL, exclude_id="i-1") is False
        assert await repo.exists_by_url(f"{_BASE_URL}/other") is False

    @pytest.mark.asyncio
    async def test_update_and_delete_report_whether_a_row_was_touched(self, repo_class, model, collection_name):
        db = FakeDatabase()
        repo = repo_class(db)
        await repo.create(_instance(model))

        assert await repo.update("i-1", {"name": "Renamed"}) is True
        assert (await repo.get_by_id("i-1")).name == "Renamed"
        assert await repo.update("absent", {"name": "Renamed"}) is False
        assert await repo.delete("i-1") is True
        assert await repo.get_by_id("i-1") is None
        assert await repo.delete("i-1") is False


class TestGitLabDefaultInstance:
    @pytest.mark.asyncio
    async def test_the_default_has_to_be_active_as_well_as_flagged(self):
        db = FakeDatabase()
        repo = GitLabInstanceRepository(db)
        await repo.create(_instance(GitLabInstance, "retired", name="Retired", is_default=True, is_active=False))
        await repo.create(_instance(GitLabInstance, "live", name="Live", is_default=True))

        default = await repo.get_default()

        assert default is not None
        assert default.id == "live"

    @pytest.mark.asyncio
    async def test_no_default_flagged_resolves_to_nothing(self):
        db = FakeDatabase()
        repo = GitLabInstanceRepository(db)
        await repo.create(_instance(GitLabInstance))

        assert await repo.get_default() is None

    @pytest.mark.asyncio
    async def test_promoting_one_instance_demotes_the_previous_default(self):
        db = FakeDatabase()
        repo = GitLabInstanceRepository(db)
        await repo.create(_instance(GitLabInstance, "old", name="Old", is_default=True))
        await repo.create(_instance(GitLabInstance, "new", name="New"))

        assert await repo.set_as_default("new") is True

        assert (await repo.get_default()).id == "new"
        assert (await repo.get_by_id("old")).is_default is False

    @pytest.mark.asyncio
    async def test_promoting_an_absent_instance_reports_failure(self):
        db = FakeDatabase()
        repo = GitLabInstanceRepository(db)
        await repo.create(_instance(GitLabInstance, "old", name="Old", is_default=True))

        assert await repo.set_as_default("absent") is False
        assert await repo.get_default() is None
