import logging
from functools import partial
from unittest.mock import AsyncMock, patch

import pytest
from pymongo.errors import PyMongoError

from app.core.constants import TEAM_ROLE_ADMIN, TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from app.models.team import GitHubTeamBinding, GitLabGroupBinding, Team, TeamMember
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.teams import TeamRepository
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance

_INSTANCE_ID = "instance-1"
_OTHER_INSTANCE_ID = "instance-2"
_BAD_REQUEST = 400
_NOT_FOUND = 404
_NO_CONTENT = 204
_PROVIDERS = pytest.mark.parametrize(
    ("provider", "repo_class", "make_instance", "make_binding", "link_field", "other_field"),
    [
        pytest.param(
            TEAM_SOURCE_GITLAB,
            GitLabInstanceRepository,
            make_gitlab_instance,
            GitLabGroupBinding,
            "gitlab_instance_id",
            "github_instance_id",
            id="gitlab",
        ),
        pytest.param(
            TEAM_SOURCE_GITHUB,
            GitHubInstanceRepository,
            make_github_instance,
            partial(GitHubTeamBinding, org="acme"),
            "github_instance_id",
            "gitlab_instance_id",
            id="github",
        ),
    ],
)


async def _seed(db, repo_class, make_instance, project_field=None):
    repo = repo_class(db)
    await repo.create(make_instance(id=_INSTANCE_ID))
    if project_field:
        await db.projects.insert_one({"_id": "p1", "name": "p1", project_field: _INSTANCE_ID})
    return repo


def _path(provider):
    return f"/api/v1/{provider}-instances/{_INSTANCE_ID}"


@pytest.mark.asyncio
@_PROVIDERS
async def test_an_instance_a_project_links_to_is_kept_even_when_forced(
    db, client, admin_auth_headers, provider, repo_class, make_instance, make_binding, link_field, other_field
):
    repo = await _seed(db, repo_class, make_instance, link_field)

    response = await client.delete(_path(provider), params={"force": "true"}, headers=admin_auth_headers)

    assert response.status_code == _BAD_REQUEST
    assert "1 projects are still linked" in response.json()["detail"]
    assert "Delete those projects first" in response.json()["detail"]
    assert await repo.get_by_id(_INSTANCE_ID) is not None


@pytest.mark.asyncio
@_PROVIDERS
async def test_a_project_linked_through_the_other_provider_field_does_not_block_the_delete(
    db, client, admin_auth_headers, provider, repo_class, make_instance, make_binding, link_field, other_field
):
    repo = await _seed(db, repo_class, make_instance, other_field)

    response = await client.delete(_path(provider), headers=admin_auth_headers)

    assert response.status_code == _NO_CONTENT
    assert await repo.get_by_id(_INSTANCE_ID) is None


@pytest.mark.asyncio
@_PROVIDERS
async def test_a_failed_team_cleanup_keeps_the_instance_so_the_delete_can_be_retried(
    db, client, admin_auth_headers, provider, repo_class, make_instance, make_binding, link_field, other_field
):
    repo = await _seed(db, repo_class, make_instance)
    failing = AsyncMock(side_effect=PyMongoError("not primary"))

    with patch.object(TeamRepository, "remove_instance", failing), pytest.raises(PyMongoError):
        await client.delete(_path(provider), headers=admin_auth_headers)

    assert await repo.get_by_id(_INSTANCE_ID) is not None


@pytest.mark.asyncio
@_PROVIDERS
async def test_an_unknown_instance_is_not_found(
    db, client, admin_auth_headers, provider, repo_class, make_instance, make_binding, link_field, other_field
):
    response = await client.delete(_path(provider), headers=admin_auth_headers)

    assert response.status_code == _NOT_FOUND


@pytest.mark.live_mongo
@pytest.mark.asyncio
@_PROVIDERS
async def test_a_deleted_instance_leaves_no_binding_and_no_member_its_sync_added(
    db, client, admin_auth_headers, caplog, provider, repo_class, make_instance, make_binding, link_field, other_field
):
    """Only the instance's own sync ever retires the members it added, and none runs once it is gone."""
    await _seed(db, repo_class, make_instance)
    synced = team_source(provider, _INSTANCE_ID)
    elsewhere = team_source(provider, _OTHER_INSTANCE_ID)
    teams = TeamRepository(db)
    await teams.create(
        Team(
            id="mixed",
            name="Mixed",
            bindings=[
                make_binding(instance_id=_INSTANCE_ID, external_id=77),
                make_binding(instance_id=_OTHER_INSTANCE_ID, external_id=77),
            ],
            members=[
                TeamMember(user_id="synced", source=synced),
                TeamMember(user_id="manual", role=TEAM_ROLE_ADMIN),
                TeamMember(user_id="elsewhere", source=elsewhere),
            ],
        )
    )
    await teams.create(
        Team(
            id="synced-only",
            name="Synced Only",
            bindings=[make_binding(instance_id=_INSTANCE_ID, external_id=78)],
            members=[TeamMember(user_id="synced", source=synced, role=TEAM_ROLE_ADMIN)],
        )
    )
    await teams.create(
        Team(
            id="unbound",
            name="Unbound",
            members=[TeamMember(user_id="left-behind", source=synced), TeamMember(user_id="manual")],
        )
    )
    await teams.create(
        Team(
            id="unrelated",
            name="Unrelated",
            bindings=[make_binding(instance_id=_OTHER_INSTANCE_ID, external_id=79)],
            members=[TeamMember(user_id="elsewhere", source=elsewhere)],
        )
    )
    unrelated = await teams.get_raw_by_id("unrelated")

    with caplog.at_level(logging.WARNING, logger="app.api.v1.helpers.vcs_instances"):
        response = await client.delete(_path(provider), headers=admin_auth_headers)

    assert response.status_code == _NO_CONTENT
    assert "detached from 3 teams" in caplog.text
    mixed = await teams.get_raw_by_id("mixed")
    assert [binding["instance_id"] for binding in mixed["bindings"]] == [_OTHER_INSTANCE_ID]
    assert [member["user_id"] for member in mixed["members"]] == ["manual", "elsewhere"]
    synced_only = await teams.get_raw_by_id("synced-only")
    assert (synced_only["bindings"], synced_only["members"]) == ([], [])
    assert [member["user_id"] for member in (await teams.get_raw_by_id("unbound"))["members"]] == ["manual"]
    assert await teams.get_raw_by_id("unrelated") == unrelated
