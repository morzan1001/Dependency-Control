"""Identity matching trusts only what an account has proven: an unverified email or a bare username
names whoever typed it, not the person the external identity belongs to."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.api.deps import _resolve_initial_member_id
from app.models.gitlab_api import GitLabMember
from app.repositories.users import UserRepository
from app.services.github import GitHubEmailLookup, GitHubService
from app.services.gitlab import GitLabService
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance

_NOT_FOUND = 404
_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)
_VERIFIED = {"_id": "u-ada", "username": "ada", "email": "ada@corp.com", "is_verified": True, "permissions": []}
_UNVERIFIED = {"_id": "u-grace", "username": "grace", "email": "grace@corp.com", "is_verified": False}


async def _db(*users: dict) -> FakeDatabase:
    db = FakeDatabase()
    await db.users.insert_one({"_id": "admin-1", "username": "admin", "email": "admin@test.com"})
    for user in users:
        await db.users.insert_one(dict(user))
    return db


class TestTeamMemberAdd:
    @staticmethod
    async def _add(db: FakeDatabase, email: str, admin_user):
        from app.api.v1.endpoints.teams import add_team_member
        from app.schemas.team import TeamMemberAdd

        await db.teams.insert_one(
            {
                "_id": "team-1",
                "name": "Team",
                "members": [{"user_id": "admin-1", "role": "admin"}],
                "created_at": _TIMESTAMP,
                "updated_at": _TIMESTAMP,
            }
        )
        with patch("app.api.v1.endpoints.teams.get_team_with_access", new_callable=AsyncMock):
            return await add_team_member(
                team_id="team-1", member_in=TeamMemberAdd(email=email), current_user=admin_user, db=db
            )

    @staticmethod
    async def _member_ids(db: FakeDatabase) -> list[str]:
        team = await db.teams.find_one({"_id": "team-1"})
        return [member["user_id"] for member in team["members"]]

    @pytest.mark.asyncio
    async def test_an_account_that_has_not_verified_the_email_is_not_added(self, admin_user):
        db = await _db(_UNVERIFIED)

        with pytest.raises(HTTPException) as exc_info:
            await self._add(db, "grace@corp.com", admin_user)

        assert exc_info.value.status_code == _NOT_FOUND
        assert await self._member_ids(db) == ["admin-1"]

    @pytest.mark.asyncio
    async def test_the_account_that_verified_the_email_is_added_whatever_the_case(self, admin_user):
        db = await _db(_VERIFIED)

        await self._add(db, "Ada@CORP.com", admin_user)

        assert await self._member_ids(db) == ["admin-1", "u-ada"]


class TestProjectMemberAdd:
    @staticmethod
    async def _invite(db: FakeDatabase, email: str, admin_user):
        from app.api.v1.endpoints.projects import invite_user
        from app.schemas.project import ProjectMemberInvite

        await db.projects.insert_one({"_id": "p-1", "name": "Project", "members": []})
        with (
            patch(
                "app.api.v1.endpoints.projects.check_project_access",
                new=AsyncMock(return_value=SimpleNamespace(name="Project")),
            ),
            patch("app.api.v1.endpoints.projects.send_project_member_added_email"),
            patch("app.api.v1.endpoints.projects.deps.get_system_settings", new_callable=AsyncMock),
        ):
            return await invite_user(
                project_id="p-1",
                invite_in=ProjectMemberInvite(email=email),
                background_tasks=BackgroundTasks(),
                current_user=admin_user,
                db=db,
            )

    @staticmethod
    async def _member_ids(db: FakeDatabase) -> list[str]:
        project = await db.projects.find_one({"_id": "p-1"})
        return [member["user_id"] for member in project["members"]]

    @pytest.mark.asyncio
    async def test_an_account_that_has_not_verified_the_email_is_not_added(self, admin_user):
        db = await _db(_UNVERIFIED)

        with pytest.raises(HTTPException) as exc_info:
            await self._invite(db, "grace@corp.com", admin_user)

        assert exc_info.value.status_code == _NOT_FOUND
        assert await self._member_ids(db) == []

    @pytest.mark.asyncio
    async def test_the_account_that_verified_the_email_is_added_whatever_the_case(self, admin_user):
        db = await _db(_VERIFIED)

        await self._invite(db, "Ada@CORP.com", admin_user)

        assert await self._member_ids(db) == ["u-ada"]


class TestCiInitialProjectAdmin:
    @pytest.mark.asyncio
    async def test_an_unverified_account_holding_the_job_email_is_not_made_admin(self):
        user_repo = UserRepository(await _db(_UNVERIFIED))

        assert await _resolve_initial_member_id(user_repo, "grace@corp.com") is None

    @pytest.mark.asyncio
    async def test_the_account_that_verified_the_job_email_is_made_admin_whatever_the_case(self):
        user_repo = UserRepository(await _db(_VERIFIED))

        assert await _resolve_initial_member_id(user_repo, "ADA@corp.com") == "u-ada"


class TestGitLabTeamSync:
    @staticmethod
    async def _resolved(member: GitLabMember, *users: dict) -> list[str]:
        service = GitLabService(make_gitlab_instance())
        members, _ = await service._build_team_members([member], UserRepository(await _db(*users)))
        return [m.user_id for m in members]

    @pytest.mark.asyncio
    async def test_a_member_sharing_only_the_username_of_an_account_is_not_resolved(self):
        member = GitLabMember(username="ada", email="ada@personal.example", access_level=30)

        assert await self._resolved(member, _VERIFIED) == []

    @pytest.mark.asyncio
    async def test_a_member_whose_email_the_account_has_not_verified_is_not_resolved(self):
        member = GitLabMember(username="grace-gl", email="grace@corp.com", access_level=30)

        assert await self._resolved(member, _UNVERIFIED) == []

    @pytest.mark.asyncio
    async def test_a_member_whose_email_the_account_verified_is_resolved_whatever_the_case(self):
        member = GitLabMember(username="ada-gl", email="Ada@Corp.com", access_level=30)

        assert await self._resolved(member, _VERIFIED) == ["u-ada"]


class TestGitHubTeamSync:
    @staticmethod
    async def _resolved(login: str, public_email: str | None, *users: dict) -> list[str]:
        service = GitHubService(make_github_instance(access_token="ghp-secret", sync_teams=True))
        lookup = AsyncMock(return_value=GitHubEmailLookup(public_email))
        with patch.object(service, "get_user_public_email", new=lookup):
            members, _, _ = await service._build_team_members(
                [{"login": login, "role": "member"}], UserRepository(await _db(*users))
            )
        return [m.user_id for m in members]

    @pytest.mark.asyncio
    async def test_a_login_equal_to_the_username_of_an_account_is_not_resolved(self):
        assert await self._resolved("ada", None, _VERIFIED) == []

    @pytest.mark.asyncio
    async def test_a_public_email_the_account_has_not_verified_is_not_resolved(self):
        assert await self._resolved("grace-gh", "grace@corp.com", _UNVERIFIED) == []

    @pytest.mark.asyncio
    async def test_a_public_email_the_account_verified_is_resolved_whatever_the_case(self):
        assert await self._resolved("ada-gh", "Ada@Corp.com", _VERIFIED) == ["u-ada"]
