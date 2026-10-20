"""Driven through FakeDatabase: asserting on query documents misses a dropped .skip() and punishes rewrites."""

import pytest

from app.models.github_instance import GitHubInstance
from app.models.gitlab_instance import GitLabInstance
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from tests.mocks.fake_mongo import FakeDatabase

_CREATED_BY = "admin"
_TOKEN = "glpat-secret"
_BASE_URL = "https://vcs.example.com"

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
    async def test_an_issuer_claim_is_matched_with_its_trailing_slash_stripped(
        self, repo_class, model, collection_name
    ):
        db = FakeDatabase()
        repo = repo_class(db)
        await repo.create(_instance(model))

        found = await repo.get_by_url(f"{_BASE_URL}/")

        assert found is not None
        assert found.id == "i-1"

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
    async def test_update_answers_with_the_stored_row_and_delete_reports_a_touch(
        self, repo_class, model, collection_name
    ):
        db = FakeDatabase()
        repo = repo_class(db)
        await repo.create(_instance(model))

        assert (await repo.update("i-1", {"name": "Renamed"})).name == "Renamed"
        assert await repo.update("absent", {"name": "Renamed"}) is None
        assert await repo.delete("i-1") is True
        assert await repo.get_by_id("i-1") is None
        assert await repo.delete("i-1") is False
