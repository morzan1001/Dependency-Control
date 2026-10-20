"""Team membership is access to the projects a binding lands, so every writer names what it writes."""

from datetime import datetime, timezone

import pytest

from app.core.constants import TEAM_ROLE_ADMIN, TEAM_ROLE_MEMBER
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase


def test_no_update_document_reaches_a_team_unread():
    """A pass-through update would let a future caller write a binding past every purpose-built writer's checks."""
    assert not hasattr(TeamRepository, "update_raw")


def test_no_read_matches_teams_by_name():
    """Names are neither unique across instances nor anyone's but the team admin's to set."""
    assert not hasattr(TeamRepository, "get_by_name")
    assert not hasattr(TeamRepository, "find_raw_unbound_for_instance")


_STALE = datetime(2020, 1, 1, tzinfo=timezone.utc)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "write",
    [
        lambda repo: repo.update("t-1", {"name": "Renamed"}),
        lambda repo: repo.add_member("t-1", {"user_id": "u-new", "role": TEAM_ROLE_MEMBER}),
        lambda repo: repo.remove_member("t-1", "u-member"),
        lambda repo: repo.update_member_role("t-1", "u-member", TEAM_ROLE_ADMIN),
        lambda repo: repo.remove_user_from_all("u-member"),
    ],
    ids=["update", "add_member", "remove_member", "update_member_role", "remove_user_from_all"],
)
async def test_every_team_write_stamps_updated_at_itself(write):
    db = FakeDatabase()
    members = [{"user_id": "u-admin", "role": TEAM_ROLE_ADMIN}, {"user_id": "u-member", "role": TEAM_ROLE_MEMBER}]
    await db.teams.insert_one({"_id": "t-1", "name": "Payments", "members": members, "updated_at": _STALE})

    await write(TeamRepository(db))

    assert (await db.teams.find_one({"_id": "t-1"}))["updated_at"] > _STALE
