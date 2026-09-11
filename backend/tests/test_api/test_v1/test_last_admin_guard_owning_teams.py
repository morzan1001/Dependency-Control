"""Taking the project's last directly-named admin, when an owning team can supply another.

The guard exists so a project cannot be left with nobody able to administer it. An owning team's
admins are project admins, so the question it really asks is whether *any* owner supplies one —
and answering it from the mirrored scalar refuses a removal the co-owner makes perfectly safe,
while answering it too loosely leaves a project stranded.
"""

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.projects import remove_project_member, update_project_member
from app.models.user import User
from app.schemas.project import ProjectMemberUpdate
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "p-admins"
_LAST_ADMIN = "u-admin"

_CALLER = User(id="superuser", username="su", email="su@test.com", permissions=["project:update"])

_NO_ADMINS = [{"user_id": "u-plain", "role": "member"}]
_HAS_ADMIN = [{"user_id": "u-team-admin", "role": "admin"}]


async def _seed(db, *, owners: list[str], alpha_members: list, bravo_members: list):
    await db.teams.insert_one({"_id": "alpha", "name": "Alpha", "members": alpha_members})
    await db.teams.insert_one({"_id": "bravo", "name": "Bravo", "members": bravo_members})
    await db.projects.insert_one(
        {
            "_id": _PROJECT,
            "name": "admins",
            "team_ids": owners,
            # The scalar names the owner that supplies nobody, which is the half a reader of it sees.
            "team_id": owners[0] if owners else None,
            "members": [{"user_id": _LAST_ADMIN, "role": "admin"}, {"user_id": "u-viewer", "role": "viewer"}],
        }
    )
    return db


def _remaining_roles(db) -> dict[str, str]:
    return {m["user_id"]: m["role"] for m in db.projects._docs[_PROJECT]["members"]}


@pytest.mark.asyncio
async def test_a_co_owner_supplying_an_admin_releases_the_guard():
    db = await _seed(FakeDatabase(), owners=["alpha", "bravo"], alpha_members=_NO_ADMINS, bravo_members=_HAS_ADMIN)

    await remove_project_member(_PROJECT, _LAST_ADMIN, _CALLER, db)

    assert _remaining_roles(db) == {"u-viewer": "viewer"}


@pytest.mark.asyncio
async def test_a_co_owner_supplying_an_admin_releases_the_demotion_guard():
    db = await _seed(FakeDatabase(), owners=["alpha", "bravo"], alpha_members=_NO_ADMINS, bravo_members=_HAS_ADMIN)

    await update_project_member(_PROJECT, _LAST_ADMIN, ProjectMemberUpdate(role="viewer"), _CALLER, db)

    assert _remaining_roles(db) == {_LAST_ADMIN: "viewer", "u-viewer": "viewer"}


@pytest.mark.asyncio
async def test_no_owner_supplying_an_admin_keeps_the_guard():
    """The half that must not loosen: neither owner has an admin, so the project would be stranded."""
    db = await _seed(FakeDatabase(), owners=["alpha", "bravo"], alpha_members=_NO_ADMINS, bravo_members=_NO_ADMINS)

    with pytest.raises(HTTPException) as raised:
        await remove_project_member(_PROJECT, _LAST_ADMIN, _CALLER, db)

    assert raised.value.status_code == 400
    assert _remaining_roles(db)[_LAST_ADMIN] == "admin"


@pytest.mark.asyncio
async def test_an_unowned_project_keeps_the_guard():
    db = await _seed(FakeDatabase(), owners=[], alpha_members=_HAS_ADMIN, bravo_members=_HAS_ADMIN)

    with pytest.raises(HTTPException) as raised:
        await remove_project_member(_PROJECT, _LAST_ADMIN, _CALLER, db)

    assert raised.value.status_code == 400


@pytest.mark.asyncio
async def test_an_owner_that_no_longer_exists_supplies_nobody():
    db = await _seed(FakeDatabase(), owners=["deleted-team"], alpha_members=_HAS_ADMIN, bravo_members=_HAS_ADMIN)

    with pytest.raises(HTTPException) as raised:
        await remove_project_member(_PROJECT, _LAST_ADMIN, _CALLER, db)

    assert raised.value.status_code == 400
