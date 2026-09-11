"""The member list GET /projects/{id} returns, and the access decision it doubles as.

The endpoint merges the owning teams' members into the project's own in one aggregation and then
answers 403 from the merged list, so the merge *is* the read gate here. Under several owners the
join is one-to-many, and the two ways that goes wrong pull in opposite directions: a merge that
keeps one team denies a co-owner who should be let in, and a merge that reaches past ``team_ids``
lets in someone no owner ever named.

Every case runs twice — once against the attrappe and once, marked ``live_mongo``, against a real
server, because the fan-out an unwound one-to-many join produces belongs to the real engine.
"""

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.projects import read_project
from app.core.permissions import Permissions
from app.models.user import User

_PROJECT = "p-merge"

_ALPHA = {
    "_id": "alpha",
    "name": "Alpha",
    "members": [{"user_id": "u-both", "role": "member"}, {"user_id": "u-alpha", "role": "admin"}],
}
_BRAVO = {
    "_id": "bravo",
    "name": "Bravo",
    "members": [{"user_id": "u-both", "role": "admin"}, {"user_id": "u-bravo", "role": "member"}],
}
# Exists, has members, owns nothing.
_ZULU = {"_id": "zulu", "name": "Zulu", "members": [{"user_id": "u-zulu", "role": "admin"}]}

_USER_IDS = ["u-both", "u-alpha", "u-bravo", "u-direct", "u-zulu"]

_TEAM_ORDERS = [(_ALPHA, _BRAVO), (_BRAVO, _ALPHA)]
_ORDER_IDS = ["alpha-first", "bravo-first"]


def _user(uid: str, *permissions: str) -> User:
    granted = list(permissions) or [Permissions.PROJECT_READ]
    return User(id=uid, username=uid, email=f"{uid}@test.com", permissions=granted)


async def _seed(db, *, team_order=(_ALPHA, _BRAVO), team_ids: list[str] | None = None):
    """The scalar names one owner, as every project's does while the mirror is still written."""
    for team in (*team_order, _ZULU):
        await db.teams.insert_one(dict(team))
    for uid in _USER_IDS:
        await db.users.insert_one({"_id": uid, "username": f"name-{uid}"})
    owners = ["alpha", "bravo"] if team_ids is None else team_ids
    await db.projects.insert_one(
        {
            "_id": _PROJECT,
            "name": "merge",
            "team_ids": owners,
            "team_id": owners[0] if owners else None,
            "members": [{"user_id": "u-direct", "role": "editor"}],
        }
    )
    return db


def _roles(project) -> dict[str, str]:
    return {member.user_id: member.role for member in project.members}


async def _assert_the_stronger_of_two_owning_teams_wins(db) -> None:
    """A user one owner calls a plain member and another calls an admin is an admin here."""
    project = await read_project(_PROJECT, _user("u-both"), db)

    assert _roles(project)["u-both"] == "admin"


async def _assert_every_owner_brings_its_members_and_no_one_else(db) -> None:
    project = await read_project(_PROJECT, _user("u-direct"), db)

    assert _roles(project) == {
        "u-direct": "editor",
        "u-both": "admin",
        "u-alpha": "admin",
        "u-bravo": "viewer",
    }


async def _assert_the_project_is_answered_once(db) -> None:
    """One project, however many owners: a join that fans out and is then read at index zero
    answers from a single owner and drops the rest."""
    project = await read_project(_PROJECT, _user("u-direct"), db)

    assert project.id == _PROJECT
    assert sorted(project.team_ids) == ["alpha", "bravo"]


async def _assert_a_member_of_either_owner_may_read(db) -> None:
    for uid in ("u-alpha", "u-bravo", "u-both"):
        assert (await read_project(_PROJECT, _user(uid), db)).id == _PROJECT


async def _assert_a_stranger_is_refused(db) -> None:
    for uid in ("u-zulu", "u-nobody"):
        with pytest.raises(HTTPException) as raised:
            await read_project(_PROJECT, _user(uid), db)
        assert raised.value.status_code == 403


async def _assert_the_inherited_role_names_the_team_that_granted_it(db) -> None:
    project = await read_project(_PROJECT, _user("u-direct"), db)
    inherited = {member.user_id: member.inherited_from for member in project.members}

    assert inherited["u-alpha"] == "Team: Alpha"
    assert inherited["u-bravo"] == "Team: Bravo"
    assert inherited["u-both"] == "Team: Bravo"
    assert inherited["u-direct"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("team_order", _TEAM_ORDERS, ids=_ORDER_IDS)
async def test_the_stronger_of_two_owning_teams_wins(db, team_order):
    """Both insertion orders, because the join answers in the teams collection's own and a
    first-wins merge passes under exactly one of them."""
    await _assert_the_stronger_of_two_owning_teams_wins(await _seed(db, team_order=team_order))


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("team_order", _TEAM_ORDERS, ids=_ORDER_IDS)
async def test_the_stronger_of_two_owning_teams_wins_on_real_mongo(db, team_order):
    await _assert_the_stronger_of_two_owning_teams_wins(await _seed(db, team_order=team_order))


@pytest.mark.asyncio
async def test_every_owner_brings_its_members_and_no_one_else(db):
    await _assert_every_owner_brings_its_members_and_no_one_else(await _seed(db))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_every_owner_brings_its_members_and_no_one_else_on_real_mongo(db):
    await _assert_every_owner_brings_its_members_and_no_one_else(await _seed(db))


@pytest.mark.asyncio
async def test_the_project_is_answered_once(db):
    await _assert_the_project_is_answered_once(await _seed(db))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_project_is_answered_once_on_real_mongo(db):
    await _assert_the_project_is_answered_once(await _seed(db))


@pytest.mark.asyncio
async def test_a_member_of_either_owner_may_read(db):
    await _assert_a_member_of_either_owner_may_read(await _seed(db))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_member_of_either_owner_may_read_on_real_mongo(db):
    await _assert_a_member_of_either_owner_may_read(await _seed(db))


@pytest.mark.asyncio
async def test_a_stranger_is_refused(db):
    await _assert_a_stranger_is_refused(await _seed(db))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_stranger_is_refused_on_real_mongo(db):
    await _assert_a_stranger_is_refused(await _seed(db))


@pytest.mark.asyncio
async def test_the_inherited_role_names_the_team_that_granted_it(db):
    await _assert_the_inherited_role_names_the_team_that_granted_it(await _seed(db))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_inherited_role_names_the_team_that_granted_it_on_real_mongo(db):
    await _assert_the_inherited_role_names_the_team_that_granted_it(await _seed(db))


@pytest.mark.asyncio
async def test_a_direct_membership_is_not_replaced_by_a_team_one(db):
    """u-direct is an editor by name; no owning team may overwrite or duplicate that entry."""
    await _seed(db)
    await db.teams.update_one({"_id": "alpha"}, {"$push": {"members": {"user_id": "u-direct", "role": "admin"}}})

    project = await read_project(_PROJECT, _user("u-direct"), db)

    assert _roles(project)["u-direct"] == "editor"
    assert sum(1 for member in project.members if member.user_id == "u-direct") == 1


@pytest.mark.asyncio
async def test_a_project_no_team_owns_answers_its_own_members(db):
    project = await read_project(_PROJECT, _user("u-direct"), await _seed(db, team_ids=[]))

    assert _roles(project) == {"u-direct": "editor"}


@pytest.mark.asyncio
async def test_an_owner_that_no_longer_exists_is_skipped(db):
    project = await read_project(_PROJECT, _user("u-alpha"), await _seed(db, team_ids=["alpha", "deleted-team"]))

    assert set(_roles(project)) == {"u-direct", "u-alpha", "u-both"}


@pytest.mark.asyncio
async def test_a_member_without_project_read_is_refused(db):
    await _seed(db)

    with pytest.raises(HTTPException) as raised:
        await read_project(_PROJECT, _user("u-alpha", Permissions.ANALYTICS_READ), db)

    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_read_all_reads_a_project_it_owns_no_part_of(db):
    await _seed(db)

    assert (await read_project(_PROJECT, _user("u-zulu", Permissions.PROJECT_READ_ALL), db)).id == _PROJECT
