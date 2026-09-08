"""Membership writes that cannot be raced.

Every one of these was a read-then-write: a snapshot decided, and two requests holding the same
snapshot both wrote. The guard is the write's own filter now, so the second one finds nothing.
"""

import asyncio
from datetime import datetime, timezone

import pytest

from app.core.constants import PROJECT_ROLE_ADMIN, PROJECT_ROLE_VIEWER, TEAM_ROLE_ADMIN, TEAM_ROLE_MEMBER
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_TEAM_ID = "team-1"
_PROJECT_ID = "project-1"
_ADMIN_A = "admin-a"
_ADMIN_B = "admin-b"
_NEWCOMER = "newcomer"


def _team_doc(members: list[tuple[str, str]]) -> dict:
    return {
        "_id": _TEAM_ID,
        "name": "Test Team",
        "members": [{"user_id": user_id, "role": role} for user_id, role in members],
        "created_at": _NOW,
        "updated_at": _NOW,
    }


def _project_doc(members: list[tuple[str, str]]) -> dict:
    return {
        "_id": _PROJECT_ID,
        "name": "Test Project",
        "members": [{"user_id": user_id, "role": role} for user_id, role in members],
    }


def _members(doc: dict) -> list[tuple[str, str]]:
    return [(m["user_id"], m["role"]) for m in doc["members"]]


def _admins(doc: dict, admin_role: str) -> list[str]:
    return [m["user_id"] for m in doc["members"] if m["role"] == admin_role]


@pytest.mark.asyncio
async def test_two_concurrent_adds_of_one_user_leave_one_team_member() -> None:
    db = FakeDatabase()
    await db.teams.insert_one(_team_doc([(_ADMIN_A, TEAM_ROLE_ADMIN)]))
    repo = TeamRepository(db)
    member = {"user_id": _NEWCOMER, "role": TEAM_ROLE_MEMBER}

    accepted = await asyncio.gather(
        repo.add_member(_TEAM_ID, dict(member), _NOW),
        repo.add_member(_TEAM_ID, dict(member), _NOW),
    )

    assert accepted.count(True) == 1
    assert _members(await db.teams.find_one({"_id": _TEAM_ID})) == [
        (_ADMIN_A, TEAM_ROLE_ADMIN),
        (_NEWCOMER, TEAM_ROLE_MEMBER),
    ]


@pytest.mark.asyncio
async def test_two_concurrent_invites_of_one_user_leave_one_project_member() -> None:
    db = FakeDatabase()
    await db.projects.insert_one(_project_doc([(_ADMIN_A, PROJECT_ROLE_ADMIN)]))
    repo = ProjectRepository(db)
    member = {"user_id": _NEWCOMER, "role": PROJECT_ROLE_VIEWER}

    accepted = await asyncio.gather(
        repo.add_member(_PROJECT_ID, dict(member)),
        repo.add_member(_PROJECT_ID, dict(member)),
    )

    assert accepted.count(True) == 1
    assert _members(await db.projects.find_one({"_id": _PROJECT_ID})) == [
        (_ADMIN_A, PROJECT_ROLE_ADMIN),
        (_NEWCOMER, PROJECT_ROLE_VIEWER),
    ]


@pytest.mark.asyncio
async def test_two_admins_removing_each_other_leave_the_team_one_admin() -> None:
    db = FakeDatabase()
    await db.teams.insert_one(_team_doc([(_ADMIN_A, TEAM_ROLE_ADMIN), (_ADMIN_B, TEAM_ROLE_ADMIN)]))
    repo = TeamRepository(db)

    accepted = await asyncio.gather(
        repo.remove_member(_TEAM_ID, _ADMIN_B, _NOW),
        repo.remove_member(_TEAM_ID, _ADMIN_A, _NOW),
    )

    assert accepted.count(True) == 1
    assert len(_admins(await db.teams.find_one({"_id": _TEAM_ID}), TEAM_ROLE_ADMIN)) == 1


@pytest.mark.asyncio
async def test_removing_a_plain_member_needs_no_second_admin() -> None:
    db = FakeDatabase()
    await db.teams.insert_one(_team_doc([(_ADMIN_A, TEAM_ROLE_ADMIN), (_NEWCOMER, TEAM_ROLE_MEMBER)]))

    assert await TeamRepository(db).remove_member(_TEAM_ID, _NEWCOMER, _NOW) is True
    assert _members(await db.teams.find_one({"_id": _TEAM_ID})) == [(_ADMIN_A, TEAM_ROLE_ADMIN)]


@pytest.mark.asyncio
async def test_two_admins_removing_each_other_leave_the_project_one_admin() -> None:
    db = FakeDatabase()
    await db.projects.insert_one(_project_doc([(_ADMIN_A, PROJECT_ROLE_ADMIN), (_ADMIN_B, PROJECT_ROLE_ADMIN)]))
    repo = ProjectRepository(db)

    accepted = await asyncio.gather(
        repo.remove_member(_PROJECT_ID, _ADMIN_B, require_another_admin=True),
        repo.remove_member(_PROJECT_ID, _ADMIN_A, require_another_admin=True),
    )

    assert accepted.count(True) == 1
    assert len(_admins(await db.projects.find_one({"_id": _PROJECT_ID}), PROJECT_ROLE_ADMIN)) == 1


@pytest.mark.asyncio
async def test_two_admins_demoting_each_other_leave_the_project_one_admin() -> None:
    db = FakeDatabase()
    await db.projects.insert_one(_project_doc([(_ADMIN_A, PROJECT_ROLE_ADMIN), (_ADMIN_B, PROJECT_ROLE_ADMIN)]))
    repo = ProjectRepository(db)
    demote = {"role": PROJECT_ROLE_VIEWER}

    accepted = await asyncio.gather(
        repo.update_member(_PROJECT_ID, _ADMIN_B, dict(demote), require_another_admin=True),
        repo.update_member(_PROJECT_ID, _ADMIN_A, dict(demote), require_another_admin=True),
    )

    assert accepted.count(True) == 1
    assert len(_admins(await db.projects.find_one({"_id": _PROJECT_ID}), PROJECT_ROLE_ADMIN)) == 1


@pytest.mark.asyncio
async def test_an_unguarded_member_update_still_writes() -> None:
    """The guard is opt-in: a team admin backs the project, so a direct demotion is allowed."""
    db = FakeDatabase()
    await db.projects.insert_one(_project_doc([(_ADMIN_A, PROJECT_ROLE_ADMIN)]))

    assert await ProjectRepository(db).update_member(_PROJECT_ID, _ADMIN_A, {"role": PROJECT_ROLE_VIEWER}) is True
    assert _members(await db.projects.find_one({"_id": _PROJECT_ID})) == [(_ADMIN_A, PROJECT_ROLE_VIEWER)]
