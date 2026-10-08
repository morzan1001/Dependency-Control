"""Two ingests racing to create a group's team: one wins on the unique index, the other owns through it."""

import asyncio
import logging
from unittest.mock import AsyncMock, patch

import pytest

from app.core.init_db import create_team_indexes
from app.models.gitlab_api import GitLabMember
from app.models.team import GitLabGroupBinding, Team
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.services.gitlab import GitLabService
from tests.mocks.gitlab import make_gitlab_instance, make_project_details, sync_team

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_BINDING = GitLabGroupBinding(instance_id="gl-1", external_id=42, path="mo")


async def test_a_losing_create_answers_with_the_team_that_won(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)

    won = await repo.create_bound(Team(id="t-first", name="GitLab Group: mo", bindings=[_BINDING]))
    lost = await repo.create_bound(Team(id="t-second", name="GitLab Group: mo", bindings=[_BINDING]))

    assert won["_id"] == "t-first"
    assert lost["_id"] == "t-first"
    assert await repo.count({}) == 1


async def test_two_ingests_of_one_new_group_both_own_through_the_one_team(db, caplog):
    await create_team_indexes(db)
    await db["users"].insert_one({"_id": "u-ada", "username": "ada", "email": "ada@corp.com", "is_verified": True})
    user_repo = UserRepository(db)
    resolve = user_repo.find_raw_by_verified_emails
    both_missed_the_team = asyncio.Barrier(2)

    async def _resolve_once_both_ingests_missed(emails: list[str]):
        await both_missed_the_team.wait()
        return await resolve(emails)

    user_repo.find_raw_by_verified_emails = _resolve_once_both_ingests_missed

    async def _ingest():
        service = GitLabService(make_gitlab_instance(id="gl-1", access_token="glpat-secret"))
        members = [GitLabMember(username="ada", email="ada@corp.com", access_level=50)]
        with patch.object(service, "get_group_members", new=AsyncMock(return_value=members)):
            return await sync_team(
                service,
                make_project_details(namespace_kind="group", namespace_id=42, namespace_path="mo"),
                db=db,
                gitlab_project_id=100,
                gitlab_project_path="mo/proj",
            )

    with (
        patch("app.services.gitlab.UserRepository", return_value=user_repo),
        caplog.at_level(logging.ERROR, logger="app.services.gitlab"),
    ):
        first, second = await asyncio.gather(_ingest(), _ingest())

    stored = await db.teams.find({}).to_list(None)
    assert len(stored) == 1
    assert first.team_ids == second.team_ids == [stored[0]["_id"]]
    assert not caplog.records
