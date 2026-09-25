"""A project's GitLab binding decides whose CI ingests land in it, so only an estate admin sets one."""

from unittest.mock import AsyncMock, patch

import pytest
from pymongo.errors import DuplicateKeyError

from app.core.init_db import create_indexes
from app.core.permissions import Permissions
from app.models.gitlab_api import GitLabProjectDetails
from app.repositories.projects import ProjectRepository
from app.services.gitlab import GitLabService
from tests.helpers.auth import bearer_headers
from tests.helpers.permission_presets import PRESET_USER

_BOUND = {"gitlab_instance_id": "gl-1", "gitlab_project_id": 4242, "gitlab_project_path": "group/sub/project"}
_UNBOUND = {"gitlab_instance_id": None, "gitlab_project_id": None, "gitlab_project_path": None}

# Shape of a gitlab_instances document as written by VcsInstanceRepository.create.
_INSTANCE = {
    "_id": "gl-1",
    "name": "Internal GitLab",
    "url": "https://gitlab.example.com",
    "oidc_audience": "dependency-control",
    "is_active": True,
    "auto_create_projects": True,
    "created_by": "admin-user",
}


def _system_manager_headers() -> dict[str, str]:
    """A project admin who also administers the estate, without the global project write grant."""
    return bearer_headers("ownerp", [*PRESET_USER, Permissions.SYSTEM_MANAGE])


def _write_superuser_headers() -> dict[str, str]:
    return bearer_headers("estate-writer", [Permissions.PROJECT_READ, Permissions.PROJECT_UPDATE])


async def _seed_instance(db, **overrides) -> None:
    await db.gitlab_instances.insert_one({**_INSTANCE, **overrides})


async def _bind(db, project_id: str = "p", **binding) -> None:
    await db.projects.update_one({"_id": project_id}, {"$set": {**_BOUND, **binding}})


async def _stored_binding(db, project_id: str = "p") -> dict:
    stored = await db.projects.find_one({"_id": project_id})
    return {key: stored.get(key) for key in _BOUND}


def _gitlab_answers(path_with_namespace: str | None):
    details = GitLabProjectDetails(path_with_namespace=path_with_namespace) if path_with_namespace else None
    return patch.object(GitLabService, "get_project_details", AsyncMock(return_value=details))


@pytest.mark.asyncio
async def test_a_project_admin_cannot_change_the_bound_project_id(client, db, owner_auth_headers_proj):
    await _seed_instance(db)
    await _bind(db)

    resp = await client.put(
        "/api/v1/projects/p", json={**_BOUND, "gitlab_project_id": 9999}, headers=owner_auth_headers_proj
    )

    assert resp.status_code == 403, resp.text
    assert await _stored_binding(db) == _BOUND


@pytest.mark.asyncio
async def test_a_project_admin_cannot_bind_an_unbound_project(client, db, owner_auth_headers_proj):
    await _seed_instance(db)

    resp = await client.put("/api/v1/projects/p", json=_BOUND, headers=owner_auth_headers_proj)

    assert resp.status_code == 403, resp.text
    assert await _stored_binding(db) == _UNBOUND


@pytest.mark.asyncio
async def test_a_project_admin_resending_the_stored_binding_saves_the_rest(client, db, owner_auth_headers_proj):
    """Clients resend the stored binding with every update, so an unchanged one is no change."""
    await _seed_instance(db)
    await _bind(db)

    resp = await client.put("/api/v1/projects/p", json={**_BOUND, "name": "renamed"}, headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    stored = await db.projects.find_one({"_id": "p"})
    assert stored["name"] == "renamed"
    assert await _stored_binding(db) == _BOUND


@pytest.mark.asyncio
async def test_a_project_admin_resending_no_binding_saves_the_rest(client, db, owner_auth_headers_proj):
    resp = await client.put("/api/v1/projects/p", json={**_UNBOUND, "name": "renamed"}, headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert (await db.projects.find_one({"_id": "p"}))["name"] == "renamed"


@pytest.mark.asyncio
async def test_a_project_admin_can_clear_the_binding(client, db, owner_auth_headers_proj):
    await _seed_instance(db)
    await _bind(db)

    resp = await client.put("/api/v1/projects/p", json=_UNBOUND, headers=owner_auth_headers_proj)

    assert resp.status_code == 200, resp.text
    assert await _stored_binding(db) == _UNBOUND


@pytest.mark.asyncio
async def test_a_half_cleared_binding_is_refused(client, db, owner_auth_headers_proj):
    await _seed_instance(db)
    await _bind(db)

    resp = await client.put("/api/v1/projects/p", json={"gitlab_instance_id": None}, headers=owner_auth_headers_proj)

    assert resp.status_code == 400, resp.text
    assert await _stored_binding(db) == _BOUND


@pytest.mark.usefixtures("owner_auth_headers_proj")
@pytest.mark.asyncio
async def test_a_system_manager_binds_with_the_path_the_instance_reports(client, db):
    await _seed_instance(db, access_token="glpat-real")

    with _gitlab_answers("real-group/real-project"):
        resp = await client.put(
            "/api/v1/projects/p", json={**_BOUND, "gitlab_project_path": "made/up"}, headers=_system_manager_headers()
        )

    assert resp.status_code == 200, resp.text
    assert await _stored_binding(db) == {
        "gitlab_instance_id": "gl-1",
        "gitlab_project_id": 4242,
        "gitlab_project_path": "real-group/real-project",
    }


@pytest.mark.asyncio
async def test_the_submitted_path_stands_when_the_instance_cannot_answer(client, db):
    await _seed_instance(db)

    resp = await client.put("/api/v1/projects/test-project-id", json=_BOUND, headers=_write_superuser_headers())

    assert resp.status_code == 200, resp.text
    assert await _stored_binding(db, "test-project-id") == _BOUND


@pytest.mark.asyncio
async def test_a_write_superuser_can_move_the_binding_to_another_project_id(client, db):
    await _seed_instance(db, access_token="glpat-real")
    await _bind(db, "test-project-id")

    with _gitlab_answers("group/other"):
        resp = await client.put(
            "/api/v1/projects/test-project-id",
            json={**_BOUND, "gitlab_project_id": 5151},
            headers=_write_superuser_headers(),
        )

    assert resp.status_code == 200, resp.text
    assert await _stored_binding(db, "test-project-id") == {
        "gitlab_instance_id": "gl-1",
        "gitlab_project_id": 5151,
        "gitlab_project_path": "group/other",
    }


@pytest.mark.usefixtures("owner_auth_headers_proj")
@pytest.mark.asyncio
async def test_binding_to_an_unknown_instance_is_not_found(client, db):
    resp = await client.put("/api/v1/projects/p", json=_BOUND, headers=_system_manager_headers())

    assert resp.status_code == 404, resp.text
    assert await _stored_binding(db) == _UNBOUND


@pytest.mark.usefixtures("owner_auth_headers_proj")
@pytest.mark.asyncio
async def test_a_binding_needs_both_the_instance_and_the_project_id(client, db):
    await _seed_instance(db)

    resp = await client.put(
        "/api/v1/projects/p", json={"gitlab_instance_id": "gl-1"}, headers=_system_manager_headers()
    )

    assert resp.status_code == 400, resp.text
    assert await _stored_binding(db) == _UNBOUND


@pytest.mark.usefixtures("owner_auth_headers_proj")
@pytest.mark.asyncio
async def test_a_gitlab_project_bound_elsewhere_is_a_conflict(client, db):
    await _seed_instance(db)
    # The fake does not enforce the partial unique index on updates; the live test below does.
    duplicate = AsyncMock(side_effect=DuplicateKeyError("E11000 duplicate key error"))

    with patch.object(ProjectRepository, "update_raw", duplicate):
        resp = await client.put("/api/v1/projects/p", json=_BOUND, headers=_system_manager_headers())

    assert resp.status_code == 409, resp.text
    assert "4242" in resp.json()["detail"]


@pytest.mark.live_mongo
@pytest.mark.usefixtures("owner_auth_headers_proj")
@pytest.mark.asyncio
async def test_the_unique_index_turns_a_second_binding_into_a_conflict(client, db):
    await create_indexes(db)
    await _seed_instance(db)
    await _bind(db, "test-project-id")

    resp = await client.put("/api/v1/projects/p", json=_BOUND, headers=_system_manager_headers())

    assert resp.status_code == 409, resp.text
    assert await _stored_binding(db) == _UNBOUND
    assert await _stored_binding(db, "test-project-id") == _BOUND
