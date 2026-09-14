"""A member added while a sync is in flight, against a real server.

The sync reads the team several HTTP round trips before it writes its members back. An admin adding
someone in that window has already been told the add succeeded, so the write that follows must be
computed from the array as the server holds it and not from the snapshot the sync started with.

A real server only: the fake hands out the stored document itself, so a merge in Python reads the
add through its own snapshot and the race it loses the member to cannot happen there.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, team_source
from app.models.team import GitHubTeamBinding, Team, TeamMember
from app.repositories.teams import TeamRepository
from app.services.github import GitHubService
from tests.mocks.github import make_github_instance

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_INSTANCE = "gh-1"
_OWN = team_source(TEAM_SOURCE_GITHUB, _INSTANCE)
_TEAM_ID = "t-pay"
_ORG_TEAMS = [{"id": 4711, "slug": "payments", "name": "Payments", "parent": None}]

# Long enough that the add is a round trip of its own inside the window, short enough to keep the
# suite quick; the measured window in production was 0.8s.
_MID_SYNC = 0.05


async def _seed(db, *, members: list[TeamMember] | None = None) -> TeamRepository:
    await db["users"].insert_one({"_id": "u-ada", "username": "ada", "email": "ada@corp.com"})
    await db["users"].insert_one({"_id": "u-added", "username": "added", "email": "added@corp.com"})
    repo = TeamRepository(db)
    await repo.create(
        Team(
            id=_TEAM_ID,
            name="Payments Guild",
            bindings=[GitHubTeamBinding(instance_id=_INSTANCE, org="acme", external_id=4711, slug="payments")],
            members=members or [],
        )
    )
    return repo


async def _sync_with_an_add_in_flight(db, added: TeamMember) -> None:
    """One ingest whose member fetch is interrupted by an admin adding a member by hand."""
    repo = TeamRepository(db)
    service = GitHubService(make_github_instance(id=_INSTANCE, access_token="ghp-secret"))

    async def _members_while_the_admin_adds_one(_org, _slug, _team_id):
        await asyncio.sleep(_MID_SYNC)
        assert await repo.add_member(_TEAM_ID, added.model_dump(), datetime.now(timezone.utc))
        return [{"login": "ada", "role": "maintainer"}]

    with (
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=_ORG_TEAMS)),
        patch.object(service, "get_team_repository", new=AsyncMock(return_value=True)),
        patch.object(service, "get_team_members", new=AsyncMock(side_effect=_members_while_the_admin_adds_one)),
        patch.object(service, "get_org_repository_map", new=AsyncMock(return_value={})),
    ):
        await service.sync_team_from_github(db, "acme", "acme/widgets")


async def _stored_members(db) -> dict[str, dict]:
    team = await TeamRepository(db).get_raw_by_id(_TEAM_ID)
    return {member["user_id"]: member for member in team["members"]}


async def _assert_a_member_added_mid_sync_is_still_there(db) -> None:
    await _seed(db)

    await _sync_with_an_add_in_flight(db, TeamMember(user_id="u-added", role="admin"))

    assert await _stored_members(db) == {
        "u-added": {"user_id": "u-added", "role": "admin", "source": "manual"},
        "u-ada": {"user_id": "u-ada", "role": "admin", "source": _OWN},
    }


async def _assert_a_member_added_mid_sync_whom_the_group_also_holds_is_not_duplicated(db) -> None:
    await _seed(db)

    await _sync_with_an_add_in_flight(db, TeamMember(user_id="u-ada", role="member"))

    assert await _stored_members(db) == {"u-ada": {"user_id": "u-ada", "role": "admin", "source": _OWN}}


async def _assert_the_departed_still_go_while_the_added_stay(db) -> None:
    """The write is still a replacement of this instance's subset, not an append to it."""
    await _seed(db, members=[TeamMember(user_id="u-gone", role="member", source=_OWN)])

    await _sync_with_an_add_in_flight(db, TeamMember(user_id="u-added", role="member"))

    assert set(await _stored_members(db)) == {"u-added", "u-ada"}


async def test_a_member_added_mid_sync_is_still_there_on_real_mongo(db):
    await _assert_a_member_added_mid_sync_is_still_there(db)


async def test_a_member_added_mid_sync_whom_the_group_also_holds_is_not_duplicated_on_real_mongo(db):
    await _assert_a_member_added_mid_sync_whom_the_group_also_holds_is_not_duplicated(db)


async def test_the_departed_still_go_while_the_added_stay_on_real_mongo(db):
    await _assert_the_departed_still_go_while_the_added_stay(db)
