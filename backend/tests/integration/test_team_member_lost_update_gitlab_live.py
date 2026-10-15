"""Live only: the fake hands out the stored document itself, so the lost-update race cannot happen there."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TEAM_SOURCE_GITLAB, team_source
from app.models.gitlab_api import GitLabMember
from app.models.team import GitLabGroupBinding, Team, TeamMember
from app.repositories.users import UserRepository
from app.repositories.teams import TeamRepository
from app.services.gitlab import GitLabService
from tests.mocks.gitlab import make_gitlab_instance, make_project_details, sync_team

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_INSTANCE = "gl-1"
_OWN = team_source(TEAM_SOURCE_GITLAB, _INSTANCE)
_TEAM_ID = "t-edge"
_GROUP_ID = 42

# Long enough for the add to be its own round trip inside the window, short enough to keep the suite quick.
_MID_SYNC = 0.05


async def _seed(db, *, members: list[TeamMember] | None = None) -> TeamRepository:
    await db["users"].insert_one({"_id": "u-ada", "username": "ada", "email": "ada@corp.com", "is_verified": True})
    await db["users"].insert_one(
        {"_id": "u-added", "username": "added", "email": "added@corp.com", "is_verified": True}
    )
    repo = TeamRepository(db)
    await repo.create(
        Team(
            id=_TEAM_ID,
            name="GitLab Group: mo",
            bindings=[GitLabGroupBinding(instance_id=_INSTANCE, external_id=_GROUP_ID, path="mo")],
            members=members or [],
        )
    )
    return repo


async def _sync_with_an_add_in_flight(db, added: TeamMember) -> None:
    team_repo = TeamRepository(db)
    user_repo = UserRepository(db)
    service = GitLabService(make_gitlab_instance(id=_INSTANCE, access_token="glpat-secret"))
    resolve = user_repo.verified_users_by_email

    async def _resolve_while_the_admin_adds_one(emails: set[str]):
        await asyncio.sleep(_MID_SYNC)
        assert await team_repo.add_member(_TEAM_ID, added.model_dump(), datetime.now(timezone.utc))
        return await resolve(emails)

    user_repo.verified_users_by_email = _resolve_while_the_admin_adds_one

    with (
        patch("app.services.gitlab.UserRepository", return_value=user_repo),
        patch.object(
            service,
            "get_group_members",
            new=AsyncMock(return_value=[GitLabMember(username="ada", email="ada@corp.com", access_level=50)]),
        ),
    ):
        await sync_team(
            service,
            db=db,
            gitlab_project_id=100,
            gitlab_project_path="mo/proj",
            project_details=make_project_details(namespace_kind="group", namespace_id=_GROUP_ID, namespace_path="mo"),
        )


async def _stored_members(db) -> dict[str, dict]:
    team = await TeamRepository(db).get_raw_by_id(_TEAM_ID)
    return {member["user_id"]: member for member in team["members"]}


async def test_a_member_added_mid_sync_is_still_there_on_real_mongo(db):
    await _seed(db)

    await _sync_with_an_add_in_flight(db, TeamMember(user_id="u-added", role="admin"))

    assert await _stored_members(db) == {
        "u-added": {"user_id": "u-added", "role": "admin", "source": "manual"},
        "u-ada": {"user_id": "u-ada", "role": "admin", "source": _OWN},
    }


async def test_a_member_added_mid_sync_whom_the_group_also_holds_keeps_the_hand_entry_on_real_mongo(db):
    await _seed(db)

    await _sync_with_an_add_in_flight(db, TeamMember(user_id="u-ada", role="member"))

    assert await _stored_members(db) == {"u-ada": {"user_id": "u-ada", "role": "member", "source": "manual"}}


async def test_the_departed_still_go_while_the_added_stay_on_real_mongo(db):
    await _seed(db, members=[TeamMember(user_id="u-gone", role="member", source=_OWN)])

    await _sync_with_an_add_in_flight(db, TeamMember(user_id="u-added", role="member"))

    assert set(await _stored_members(db)) == {"u-added", "u-ada"}
