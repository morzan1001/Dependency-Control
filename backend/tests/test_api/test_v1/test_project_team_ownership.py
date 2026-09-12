"""Changing a project's owners by hand: who may, and what ends up stored.

The project-admin gate itself is ``check_project_access`` and is tested with the rest of it; these
drive the picker past it to pin the rules that are its own — the target-team rule, the owner cap,
provenance, and the refusal to leave a project nobody can administer.

The picker sends the whole owner set, a sync's entries included, so the write has to keep what it
was handed without claiming it: the provenance a retained owner arrives with is the provenance it
keeps, or a project admin could pin a team no sync is ever allowed to retire again.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.projects import _MSG_LAST_ADMIN_OWNER, update_project
from app.core.constants import MAX_PROJECT_TEAMS
from app.models.project import Project, ProjectMember
from app.models.user import User
from app.repositories.projects import ProjectRepository, replace_team_subset_pipeline
from app.schemas.project import ProjectUpdate
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


async def _put(db, project, user, **body):
    settings = MagicMock(retention_mode=None, rescan_mode=None)
    with (
        patch(f"{MODULE}._load_project_for_update", AsyncMock(return_value=project)),
        patch(f"{MODULE}.deps.get_system_settings", AsyncMock(return_value=settings)),
        patch(f"{MODULE}._audit_license_policy_change", AsyncMock()),
    ):
        return await update_project("p-1", ProjectUpdate(**body), user, db)


async def _stored(db) -> dict:
    return await db.projects.find_one({"_id": "p-1"})


@pytest.mark.asyncio
async def test_every_team_the_user_picked_is_stored():
    project = _project()
    db = await _db_with(project, _team("t-a", _ACTOR), _team("t-b", _ACTOR), _team("t-c", _ACTOR))

    updated = await _put(db, project, _user(), team_ids=["t-c", "t-a", "t-b"])

    assert updated.team_ids == ["t-a", "t-b", "t-c"]
    assert updated.team_sources == {"t-a": "manual", "t-b": "manual", "t-c": "manual"}


@pytest.mark.asyncio
async def test_a_retained_provider_owner_keeps_its_provenance():
    """Restamping it as a hand assignment would exempt it from the retirement its own provider's
    next sync applies, so any project admin could pin a team the provider no longer resolves."""
    project = _project(
        team_ids=["gh-a"], team_sources={"gh-a": "github"}, team_id="gh-a", team_source="github"
    )
    db = await _db_with(project, _team("gh-a", "someone-else"), _team("t-new", _ACTOR))

    updated = await _put(db, project, _user(), team_ids=["gh-a", "t-new"])

    assert updated.team_sources == {"gh-a": "github", "t-new": "manual"}
    # The incumbent still owns the project, so the scalars stay where they are.
    assert updated.team_id == "gh-a"

    await ProjectRepository(db).update_raw("p-1", replace_team_subset_pipeline("github", []))

    assert (await _stored(db))["team_ids"] == ["t-new"]


@pytest.mark.asyncio
async def test_a_deselected_owner_goes_whatever_established_it():
    """Until the next GitLab sync, which puts it back if that provider still resolves it."""
    project = _project(
        team_ids=["gl-a", "t-hand"],
        team_sources={"gl-a": "gitlab", "t-hand": "manual"},
        team_id="gl-a",
        team_source="gitlab",
    )
    db = await _db_with(project, _team("gl-a", _ACTOR), _team("t-hand", _ACTOR))

    updated = await _put(db, project, _user(), team_ids=["t-hand"])

    assert updated.team_ids == ["t-hand"]
    assert updated.team_sources == {"t-hand": "manual"}
    assert updated.team_id == "t-hand"
    assert updated.team_source == "manual"


@pytest.mark.asyncio
async def test_a_retained_owner_no_provenance_names_is_read_as_a_hand_assignment():
    """Every owner carried over from the scalar era arrives with no entry, and any other reading
    would leave nothing able to retire it."""
    project = _project(team_ids=["legacy", "gl-a"], team_sources={"gl-a": "gitlab"})
    db = await _db_with(project, _team("legacy", _ACTOR), _team("gl-a", _ACTOR))

    updated = await _put(db, project, _user(), team_ids=["legacy", "gl-a"])

    assert updated.team_sources == {"legacy": "manual", "gl-a": "gitlab"}


@pytest.mark.asyncio
async def test_a_caller_cannot_hand_the_project_to_a_team_they_are_not_in():
    """Ownership grants that team's members access, so this is handing out access."""
    project = _project()
    db = await _db_with(project, _team("t-other", "someone-else"))

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _user(), team_ids=["t-other"])

    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_an_owner_the_project_already_holds_asks_nothing_of_the_caller():
    """Only the owners being gained are checked; an admin of one owner may still edit the rest."""
    project = _project(team_ids=["gl-a"], team_sources={"gl-a": "gitlab"})
    db = await _db_with(project, _team("gl-a", "someone-else"), _team("t-mine", _ACTOR))

    updated = await _put(db, project, _user(), team_ids=["gl-a", "t-mine"])

    assert updated.team_ids == ["gl-a", "t-mine"]


@pytest.mark.asyncio
async def test_a_write_superuser_may_hand_it_to_any_team():
    project = _project()
    db = await _db_with(project, _team("t-other", "someone-else"))

    updated = await _put(db, project, _superuser(), team_ids=["t-other"])

    assert updated.team_ids == ["t-other"]


@pytest.mark.asyncio
async def test_a_team_that_does_not_exist_is_not_an_owner():
    """An id nothing resolves to grants nobody anything and nothing would ever reap it."""
    project = _project()
    db = await _db_with(project)

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _superuser(), team_ids=["t-ghost"])

    assert raised.value.status_code == 404


@pytest.mark.asyncio
async def test_the_owner_cap_is_refused_before_anything_is_written():
    picked = [f"t-{n}" for n in range(MAX_PROJECT_TEAMS + 1)]
    project = _project(team_ids=["t-0"], team_sources={"t-0": "manual"})
    db = await _db_with(project, *[_team(team_id, _ACTOR) for team_id in picked])

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _superuser(), team_ids=picked)

    assert raised.value.status_code == 400
    assert str(MAX_PROJECT_TEAMS) in raised.value.detail
    assert (await _stored(db))["team_ids"] == ["t-0"]


@pytest.mark.asyncio
async def test_a_capped_project_can_be_narrowed_to_one_of_its_own_owners():
    owners = [f"t-{n}" for n in range(MAX_PROJECT_TEAMS)]
    project = _project(team_ids=owners, team_sources=dict.fromkeys(owners, "manual"))
    db = await _db_with(project, *[_team(owner, _ACTOR) for owner in owners])

    updated = await _put(db, project, _superuser(), team_ids=["t-0"])

    assert updated.team_ids == ["t-0"]


@pytest.mark.asyncio
async def test_the_picker_refuses_to_take_the_last_team_supplying_an_admin():
    """Otherwise the project is left with nobody who can put an owner back."""
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR))

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _user(), team_ids=[])

    assert raised.value.status_code == 400
    assert raised.value.detail == _MSG_LAST_ADMIN_OWNER
    assert (await _stored(db))["team_ids"] == ["t-1"]


@pytest.mark.asyncio
async def test_the_picker_refuses_a_replacement_that_supplies_no_admin():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR), _team_of_plain_members("t-2", _ACTOR))

    with pytest.raises(HTTPException) as raised:
        await _put(db, project, _user(), team_ids=["t-2"])

    assert raised.value.status_code == 400
    assert (await _stored(db))["team_ids"] == ["t-1"]


@pytest.mark.asyncio
async def test_the_picker_allows_a_replacement_that_brings_its_own_admin():
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR), _team("t-2", _ACTOR, "other-admin"))

    updated = await _put(db, project, _user(), team_ids=["t-2"])

    assert updated.team_ids == ["t-2"]


@pytest.mark.asyncio
async def test_another_owning_team_s_admin_keeps_the_deselection_open():
    project = _project(team_ids=["t-1", "t-2"], team_sources={"t-1": "manual", "t-2": "manual"})
    db = await _db_with(project, _team("t-1", _ACTOR), _team("t-2", "other-admin"))

    updated = await _put(db, project, _user(), team_ids=["t-2"])

    assert updated.team_ids == ["t-2"]


@pytest.mark.asyncio
async def test_a_direct_project_admin_is_admin_enough_to_lose_every_owning_team():
    project = _project(
        team_ids=["t-1"],
        team_sources={"t-1": "manual"},
        members=[ProjectMember(user_id=_ACTOR, role="admin")],
    )
    db = await _db_with(project, _team("t-1", _ACTOR))

    updated = await _put(db, project, _user(), team_ids=[])

    assert updated.team_ids == []


@pytest.mark.asyncio
async def test_a_write_superuser_may_empty_the_owners():
    """They can put one back, and they are the only ones who could unstick the project either way."""
    project = _project(team_ids=["t-1"], team_sources={"t-1": "manual"})
    db = await _db_with(project, _team("t-1", "someone-else"))

    updated = await _put(db, project, _superuser(), team_ids=[])

    assert updated.team_ids == []
    assert updated.team_id is None


@pytest.mark.asyncio
async def test_a_body_without_owners_leaves_every_one_of_them_alone():
    project = _project(team_ids=["gl-a"], team_sources={"gl-a": "gitlab"})
    db = await _db_with(project, _team("gl-a", _ACTOR))

    updated = await _put(db, project, _user(), name="Renamed")

    assert updated.name == "Renamed"
    assert updated.team_ids == ["gl-a"]
    assert updated.team_sources == {"gl-a": "gitlab"}


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
