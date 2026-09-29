import pytest
from fastapi import HTTPException

from app.api.v1.helpers.vcs_instances import delete_guarded
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.projects import ProjectRepository
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance

_INSTANCE_ID = "instance-1"
_BAD_REQUEST = 400
_PROVIDERS = pytest.mark.parametrize(
    ("repo_class", "make_instance", "link_field", "other_field"),
    [
        pytest.param(
            GitLabInstanceRepository, make_gitlab_instance, "gitlab_instance_id", "github_instance_id", id="gitlab"
        ),
        pytest.param(
            GitHubInstanceRepository, make_github_instance, "github_instance_id", "gitlab_instance_id", id="github"
        ),
    ],
)


async def _seed(db, repo_class, make_instance, project_field):
    repo = repo_class(db)
    instance = await repo.create(make_instance(id=_INSTANCE_ID))
    await db.projects.insert_one({"_id": "p1", "name": "p1", project_field: _INSTANCE_ID})
    return repo, instance


async def _delete(db, repo, instance, *, force=False):
    await delete_guarded(repo, ProjectRepository(db), instance, force=force, label="VCS", username="admin")


@pytest.mark.asyncio
@_PROVIDERS
async def test_an_instance_a_project_links_to_is_kept(db, repo_class, make_instance, link_field, other_field):
    repo, instance = await _seed(db, repo_class, make_instance, link_field)

    with pytest.raises(HTTPException) as refused:
        await _delete(db, repo, instance)

    assert refused.value.status_code == _BAD_REQUEST
    assert f"Set {link_field}=null" in refused.value.detail
    assert await repo.get_by_id(_INSTANCE_ID) is not None


@pytest.mark.asyncio
@_PROVIDERS
async def test_a_project_linked_through_the_other_provider_field_does_not_block_the_delete(
    db, repo_class, make_instance, link_field, other_field
):
    repo, instance = await _seed(db, repo_class, make_instance, other_field)

    await _delete(db, repo, instance)

    assert await repo.get_by_id(_INSTANCE_ID) is None


@pytest.mark.asyncio
@_PROVIDERS
async def test_force_deletes_an_instance_a_project_still_links_to(
    db, repo_class, make_instance, link_field, other_field
):
    repo, instance = await _seed(db, repo_class, make_instance, link_field)

    await _delete(db, repo, instance, force=True)

    assert await repo.get_by_id(_INSTANCE_ID) is None
