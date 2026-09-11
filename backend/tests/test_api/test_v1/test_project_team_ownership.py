"""Changing a project's owners by hand: who may, and what ends up stored.

The project-admin gate itself is ``check_project_access`` and is tested with the rest of it; these
drive the three routes past it to pin the rules that are theirs alone — the target-team rule, the
owner cap, provenance, and the refusal to leave a project nobody can administer.

The picker (``PUT`` with ``team_id``) is here alongside the two ``/teams`` routes because the last
rule has to read the same on all of them: the same guard, the same status, the same message.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.projects import (
    _MSG_LAST_ADMIN_OWNER,
    add_project_team,
    remove_project_team,
    update_project,
)
from app.core.constants import MAX_PROJECT_TEAMS
from app.models.project import Project, ProjectMember
from app.models.user import User
from app.repositories.projects import ProjectRepository, replace_team_subset_pipeline
from app.schemas.project import ProjectTeamAssignment, ProjectUpdate
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


def _team_of_plain_members(team_id: str, *members: str) -> dict:
    return {"_id": team_id, "name": team_id, "members": [{"user_id": m, "role": "member"} for m in members]}


def _project(**ownership) -> Project:
    return Project(id="p-1", name="demo", **ownership)


async def _add(db, project, team_id, user):
    with patch(f"{MODULE}._load_project_for_update", AsyncMock(return_value=project)):
        return await add_project_team("p-1", ProjectTeamAssignment(team_id=team_id), user, db)


async def _remove(db, project, team_id, user):
    with patch(f"{MODULE}._load_project_for_update", AsyncMock(return_value=project)):
        return await remove_project_team("p-1", team_id, user, db)


async def _put(db, project, user, **body):
    settings = MagicMock(retention_mode=None, rescan_mode=None)
    with (
        patch(f"{MODULE}._load_project_for_update", AsyncMock(return_value=project)),
        patch(f"{MODULE}.deps.get_system_settings", AsyncMock(return_value=settings)),
        patch(f"{MODULE}._audit_license_policy_change", AsyncMock()),
    ):
        return await update_project("p-1", ProjectUpdate(**body), user, db)


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
async def test_the_picker_is_refused_at_the_cap_though_it_would_leave_the_project_under_it():
    """A decision, not an oversight: the picker replaces the manual owners, so this project would
    come out of the write with one. The cap is checked on the stored list because the check is the
    one both routes share, and a picker that alone read the post-state would be the only caller
    whose refusal depended on provenance. Refusing costs an operator one removal first; the shared
    reading is what keeps the cap impossible to argue past.
    """
    owners = [f"t-{n}" for n in range(MAX_PROJECT_TEAMS)]
    project = _project(team_ids=owners, team_sources=dict.fromkeys(owners, "manual"))
    db = await _db_with(project, _team("t-extra", _ACTOR))

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _superuser(), team_id="t-extra")

    assert raised.value.status_code == 400
    assert str(MAX_PROJECT_TEAMS) in raised.value.detail


@pytest.mark.asyncio
async def test_the_picker_at_the_cap_still_moves_the_project_to_a_team_that_already_owns_it():
    """The cap gate is skipped for an incumbent, so the picker can still narrow a capped project
    down to one of its own owners — which is the way back under the cap."""
    owners = [f"t-{n}" for n in range(MAX_PROJECT_TEAMS)]
    project = _project(team_ids=owners, team_sources=dict.fromkeys(owners, "manual"))
    db = await _db_with(project, *[_team(owner, _ACTOR) for owner in owners])

    updated = await _put(db, project, _superuser(), team_id="t-0")

    assert updated.team_ids == ["t-0"]


@pytest.mark.asyncio
async def test_adding_an_owner_twice_changes_nothing_the_second_time():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"}, team_id="t-1", team_source="manual")
    db = await _db_with(project, _team("t-1", _ACTOR))

    updated = await _add(db, project, "t-1", _user())

    assert updated.team_ids == ["t-1"]


@pytest.mark.asyncio
async def test_posting_a_provider_s_owner_does_not_claim_it_as_a_hand_assignment():
    """Restamping the entry would exempt it from the retirement its own provider's next sync
    applies, so any project admin could pin a team the provider no longer resolves."""
    project = _project(
        team_ids=["gh-a"], team_sources={"gh-a": "github"}, team_id="gh-a", team_source="github"
    )
    db = await _db_with(project, _team("gh-a", "someone-else"))

    updated = await _add(db, project, "gh-a", _user())

    assert updated.team_sources == {"gh-a": "github"}

    await ProjectRepository(db).update_raw("p-1", replace_team_subset_pipeline("github", []))

    assert (await db.projects.find_one({"_id": "p-1"}))["team_ids"] == []


@pytest.mark.asyncio
async def test_a_hand_assignment_replaces_an_owner_no_provenance_names():
    """An owner predating team_sources is read as a hand assignment, which is the only reading
    that leaves anything able to retire it."""
    project = _project(team_ids=["legacy", "gl-a"], team_sources={"gl-a": "gitlab"})
    db = await _db_with(project, _team("t-new", _ACTOR), _team("gl-a", _ACTOR))

    updated = await _put(db, project, _user(), team_id="t-new")

    assert sorted(updated.team_ids) == ["gl-a", "t-new"]
    assert updated.team_sources == {"gl-a": "gitlab", "t-new": "manual"}


@pytest.mark.asyncio
async def test_the_picker_refuses_the_last_team_supplying_an_admin_as_the_removal_does():
    """The identical outcome through DELETE is a 400, so this one is too — same guard, same
    status, same message."""
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR))

    with pytest.raises(HTTPException) as put_raised:
        await _put(db, project, _user(), team_id=None)
    with pytest.raises(HTTPException) as delete_raised:
        await _remove(db, project, "t-1", _user())

    assert put_raised.value.status_code == delete_raised.value.status_code == 400
    assert put_raised.value.detail == delete_raised.value.detail == _MSG_LAST_ADMIN_OWNER
    assert (await db.projects.find_one({"_id": "p-1"}))["team_ids"] == ["t-1"]


@pytest.mark.asyncio
async def test_the_picker_refuses_a_replacement_that_supplies_no_admin():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR), _team_of_plain_members("t-2", _ACTOR))

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _user(), team_id="t-2")

    assert raised.value.status_code == 400
    assert (await db.projects.find_one({"_id": "p-1"}))["team_ids"] == ["t-1"]


@pytest.mark.asyncio
async def test_the_picker_allows_a_replacement_that_brings_its_own_admin():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR), _team("t-2", _ACTOR, "other-admin"))

    updated = await _put(db, project, _user(), team_id="t-2")

    assert updated.team_ids == ["t-2"]


@pytest.mark.asyncio
async def test_a_write_superuser_may_empty_the_owners_through_the_picker():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", "someone-else"))

    updated = await _put(db, project, _superuser(), team_id=None)

    assert updated.team_ids == []


@pytest.mark.asyncio
async def test_the_picker_leaves_a_provider_s_owner_holding_the_project():
    project = _project(
        team_ids=["gl-a", "t-hand"], team_sources={"gl-a": "gitlab", "t-hand": "manual"}, team_id="gl-a"
    )
    db = await _db_with(project, _team("gl-a", "gitlab-admin"), _team("t-hand", _ACTOR))

    updated = await _put(db, project, _user(), team_id=None)

    assert updated.team_ids == ["gl-a"]


@pytest.mark.asyncio
async def test_the_picker_answers_404_for_a_team_that_does_not_exist():
    """POST answers 404 for an id nothing resolves to; a superuser must not slip one past here."""
    project = _project()
    db = await _db_with(project)

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _superuser(), team_id="t-ghost")

    assert raised.value.status_code == 404


@pytest.mark.asyncio
async def test_a_rename_reads_the_project_back_from_the_primary():
    """Under secondaryPreferred — the chart default — an ordinary read echoes pre-write ownership."""
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR))
    repo = ProjectRepository(db)

    with (
        patch.object(ProjectRepository, "get_by_id", AsyncMock(side_effect=AssertionError("read off-primary"))),
        patch(f"{MODULE}.ProjectRepository", return_value=repo),
    ):
        updated = await _put(db, project, _user(), name="Renamed")

    assert updated.name == "Renamed"


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
