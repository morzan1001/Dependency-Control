"""GitHub team sync: member resolution, merge semantics and the sync itself."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.github import GitHubService
from tests.mocks.github import make_github_instance


def _service() -> GitHubService:
    return GitHubService(make_github_instance(access_token="ghp-secret"))


def _user_repo(*, by_username=None, by_email=None) -> MagicMock:
    repo = MagicMock()
    repo.get_raw_by_username = AsyncMock(return_value=by_username)
    repo.get_raw_by_email_ci = AsyncMock(return_value=by_email)
    repo.create = AsyncMock()
    return repo


class TestMemberResolution:
    @pytest.mark.asyncio
    async def test_the_login_is_matched_against_the_username_first(self):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1", "username": "ada"})

        with patch.object(service, "get_user_public_email", new=AsyncMock()) as public_email:
            members = await service._build_team_members([{"login": "ada", "role": "member"}], repo)

        assert [m.user_id for m in members] == ["u-1"]
        public_email.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_public_profile_email_is_the_fallback_and_is_case_insensitive(self):
        service = _service()
        repo = _user_repo(by_username=None, by_email={"_id": "u-2", "email": "ada@corp.com"})

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value="Ada@Corp.com")):
            members = await service._build_team_members([{"login": "ada-l", "role": "member"}], repo)

        assert [m.user_id for m in members] == ["u-2"]
        repo.get_raw_by_email_ci.assert_awaited_once_with("Ada@Corp.com")

    @pytest.mark.asyncio
    async def test_a_hidden_profile_email_is_never_looked_up(self):
        service = _service()
        repo = _user_repo()

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
            assert await service._build_team_members([{"login": "ada", "role": "member"}], repo) == []

        repo.get_raw_by_email_ci.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_member_with_no_local_account_is_skipped_and_not_created(self, caplog):
        service = _service()
        repo = _user_repo()

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
            with caplog.at_level("DEBUG", logger="app.services.github"):
                members = await service._build_team_members([{"login": "dependabot", "role": "member"}], repo)

        assert members == []
        repo.create.assert_not_called()
        assert any("dependabot" in record.getMessage() for record in caplog.records if record.levelname == "DEBUG")

    @pytest.mark.asyncio
    async def test_every_resolved_member_is_tagged_github(self):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})
        members = await service._build_team_members([{"login": "ada", "role": "member"}], repo)
        assert members[0].source == "github"

    @pytest.mark.asyncio
    async def test_a_wholesale_resolution_failure_is_summarised_once(self, caplog):
        service = _service()
        repo = _user_repo()
        github_members = [{"login": f"user-{index}", "role": "member"} for index in range(3)]

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
            with caplog.at_level("INFO", logger="app.services.github"):
                assert await service._build_team_members(github_members, repo) == []

        summaries = [record.getMessage() for record in caplog.records if record.levelname == "INFO"]
        assert len(summaries) == 1
        assert "0 of 3" in summaries[0]

    @pytest.mark.asyncio
    async def test_a_fully_resolved_team_is_not_summarised(self, caplog):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})

        with caplog.at_level("INFO", logger="app.services.github"):
            await service._build_team_members([{"login": "ada", "role": "member"}], repo)

        assert [record.getMessage() for record in caplog.records if record.levelname == "INFO"] == []


class TestRoleMapping:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("github_role", "expected"), [("maintainer", "admin"), ("member", "member")])
    async def test_maintainer_becomes_admin(self, github_role, expected):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})
        members = await service._build_team_members([{"login": "ada", "role": github_role}], repo)
        assert members[0].role == expected
