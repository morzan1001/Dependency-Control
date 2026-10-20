import pytest

from app.api.v1.helpers.vcs_instances import list_page
from app.models.github_instance import GitHubInstance
from app.models.gitlab_instance import GitLabInstance
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from tests.mocks.fake_mongo import FakeDatabase

_ACTIVE_COUNT = 3


@pytest.mark.parametrize(
    ("repo_class", "model"),
    [
        pytest.param(GitLabInstanceRepository, GitLabInstance, id="gitlab"),
        pytest.param(GitHubInstanceRepository, GitHubInstance, id="github"),
    ],
)
@pytest.mark.asyncio
async def test_a_page_of_active_instances_counts_the_active_ones_only(repo_class, model):
    repo = repo_class(FakeDatabase())
    for instance_id, name, is_active in [
        *((f"a-{index}", f"Active {index}", True) for index in range(_ACTIVE_COUNT)),
        ("inactive", "Inactive", False),
    ]:
        await repo.create(
            model(
                id=instance_id,
                name=name,
                url=f"https://{instance_id}.example.com",
                created_by="admin",
                is_active=is_active,
            )
        )

    second = await list_page(repo, page=2, size=1, active_only=True, to_response=lambda instance: instance)

    assert ([instance.id for instance in second["items"]], second["total"], second["page"]) == (
        ["a-1"],
        _ACTIVE_COUNT,
        2,
    )
    everything = await list_page(repo, page=1, size=10, active_only=False, to_response=lambda instance: instance)
    assert ([instance.id for instance in everything["items"]][-1], everything["total"]) == (
        "inactive",
        _ACTIVE_COUNT + 1,
    )
