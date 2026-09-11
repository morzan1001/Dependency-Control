"""Adding and removing an owning team by hand: who may, and what ends up stored.

The project-admin gate itself is ``check_project_access`` and is tested with the rest of it; these
drive the two routes past it to pin the rules that are theirs alone — the target-team rule, the
owner cap, and the refusal to leave a project nobody can administer.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.projects import add_project_team, remove_project_team
from app.core.constants import MAX_PROJECT_TEAMS
from app.models.project import Project, ProjectMember
from app.models.user import User
from app.schemas.project import ProjectTeamAssignment
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.projects"

_ACTOR = "u-actor"


def _user(*permissions) -> User:
    return User(id=_ACTOR, username="actor", email="actor@test.com", permissions=list(permissions))


def _superuser() -> User:
    from app.core.permissions import Permissions

    return _user(Permissions.PROJECT_UPDATE)


async def _db_with(project: Project, *teams: dict) -> FakeDatabase:
    db = FakeDatabase()
    await db.projects.insert_one(project.model_dump(by_alias=True))
    for team in teams:
        await db.teams.insert_one(team)
    return db


def _team(team_id: str, *admins: str) -> dict:
    return {"_id": team_id, "name": team_id, "members": [{"user_id": a, "role": "admin"} for a in admins]}


def _project(**ownership) -> Project:
    return Project(id="p-1", name="demo", **ownership)


async def _add(db, project, team_id, user):
    with patch(f"{MODULE}._load_project_for_update", AsyncMock(return_value=project)):
        return await add_project_team("p-1", ProjectTeamAssignment(team_id=team_id), user, db)


async def _remove(db, project, team_id, user):
    with patch(f"{MODULE}._load_project_for_update", AsyncMock(return_value=project)):
        return await remove_project_team("p-1", team_id, user, db)


@pytest.mark.asyncio
async def test_an_added_owner_never_displaces_the_one_a_provider_set():
    project = _project(
        team_ids=["gl-a"], team_sources={"gl-a": "gitlab"}, team_id="gl-a", team_source="gitlab"
    )
    db = await _db_with(project, _team("t-new", _ACTOR))

    updated = await _add(db, project, "t-new", _user())

    assert sorted(updated.team_ids) == ["gl-a", "t-new"]
    assert updated.team_sources == {"gl-a": "gitlab", "t-new": "manual"}
    # The incumbent still owns the project, so the scalars stay where they are.
    assert updated.team_id == "gl-a"


@pytest.mark.asyncio
async def test_a_caller_cannot_hand_the_project_to_a_team_they_are_not_in():
    """Ownership grants that team's members access, so this is handing out access."""
    project = _project()
    db = await _db_with(project, _team("t-other", "someone-else"))

    with pytest.raises(HTTPException) as raised:
        await _add(db, project, "t-other", _user())

    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_a_write_superuser_may_hand_it_to_any_team():
    project = _project()
    db = await _db_with(project, _team("t-other", "someone-else"))

    updated = await _add(db, project, "t-other", _superuser())

    assert updated.team_ids == ["t-other"]


@pytest.mark.asyncio
async def test_a_team_that_does_not_exist_is_not_an_owner():
    """An id nothing resolves to grants nobody anything and nothing would ever reap it."""
    project = _project()
    db = await _db_with(project)

    with pytest.raises(HTTPException) as raised:
        await _add(db, project, "t-ghost", _superuser())

    assert raised.value.status_code == 404


@pytest.mark.asyncio
async def test_the_owner_cap_is_refused_rather_than_silently_truncated():
    owners = [f"t-{n}" for n in range(MAX_PROJECT_TEAMS)]
    project = _project(team_ids=owners, team_sources=dict.fromkeys(owners, "manual"))
    db = await _db_with(project, _team("t-extra", _ACTOR))

    with pytest.raises(HTTPException) as raised:
        await _add(db, project, "t-extra", _superuser())

    assert raised.value.status_code == 400


@pytest.mark.asyncio
async def test_adding_an_owner_twice_changes_nothing_the_second_time():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"}, team_id="t-1", team_source="manual")
    db = await _db_with(project, _team("t-1", _ACTOR))

    updated = await _add(db, project, "t-1", _user())

    assert updated.team_ids == ["t-1"]


@pytest.mark.asyncio
async def test_an_owner_is_removed_whichever_provider_set_it():
    """A provider's own entry is removable by hand; the next sync of that provider re-adds it,
    which is what makes the manual removal safe to allow."""
    project = _project(
        team_ids=["gl-a", "t-hand"],
        team_sources={"gl-a": "gitlab", "t-hand": "manual"},
        team_id="gl-a",
        team_source="gitlab",
    )
    db = await _db_with(project, _team("gl-a", _ACTOR), _team("t-hand", _ACTOR))

    updated = await _remove(db, project, "gl-a", _user())

    assert updated.team_ids == ["t-hand"]
    assert updated.team_sources == {"t-hand": "manual"}
    assert updated.team_id == "t-hand"
    assert updated.team_source == "manual"


@pytest.mark.asyncio
async def test_removing_a_team_that_does_not_own_the_project_is_a_404():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR), _team("t-2", _ACTOR))

    with pytest.raises(HTTPException) as raised:
        await _remove(db, project, "t-2", _user())

    assert raised.value.status_code == 404


@pytest.mark.asyncio
async def test_the_last_team_supplying_an_admin_is_not_removable():
    """Otherwise the project is left with nobody who can add an owner back."""
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR))

    with pytest.raises(HTTPException) as raised:
        await _remove(db, project, "t-1", _user())

    assert raised.value.status_code == 400
    assert (await db.projects.find_one({"_id": "p-1"}))["team_ids"] == ["t-1"]


@pytest.mark.asyncio
async def test_a_write_superuser_may_take_the_last_admin_supplying_team():
    """They can put one back, and they are the only ones who could unstick the project either way."""
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", "someone-else"))

    updated = await _remove(db, project, "t-1", _superuser())

    assert updated.team_ids == []
    assert updated.team_id is None


@pytest.mark.asyncio
async def test_a_direct_project_admin_is_admin_enough_to_lose_the_last_owning_team():
    project = _project(
        team_ids=["t-1"],
        team_sources={"t-1": "manual"},
        members=[ProjectMember(user_id=_ACTOR, role="admin")],
    )
    db = await _db_with(project, _team("t-1", _ACTOR))

    updated = await _remove(db, project, "t-1", _user())

    assert updated.team_ids == []


@pytest.mark.asyncio
async def test_another_owning_team_s_admin_keeps_the_removal_open():
    project = _project(
        team_ids=["t-1", "t-2"],
        team_sources={"t-1": "manual", "t-2": "manual"},
    )
    db = await _db_with(project, _team("t-1", _ACTOR), _team("t-2", "other-admin"))

    updated = await _remove(db, project, "t-1", _user())

    assert updated.team_ids == ["t-2"]
