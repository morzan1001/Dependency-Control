"""GitHub team sync: member resolution, merge semantics and the sync itself."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.team import TeamMember
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


def _team_repo(existing=None) -> MagicMock:
    repo = MagicMock()
    repo.get_raw_by_github_team = AsyncMock(return_value=existing)
    repo.update = AsyncMock()
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


class TestMemberMerge:
    def test_a_manually_added_member_survives_the_sync(self):
        existing = [{"user_id": "u-manual", "role": "admin", "source": "manual"}]
        merged = GitHubService._merge_team_members(existing, [TeamMember(user_id="u-gh", source="github")])
        assert merged == [
            {"user_id": "u-manual", "role": "admin", "source": "manual"},
            {"user_id": "u-gh", "role": "member", "source": "github"},
        ]

    def test_a_member_synced_from_gitlab_survives_a_github_sync(self):
        existing = [{"user_id": "u-gl", "role": "admin", "source": "gitlab"}]
        merged = GitHubService._merge_team_members(existing, [])
        assert merged == [{"user_id": "u-gl", "role": "admin", "source": "manual"}]

    def test_an_untagged_member_is_treated_as_manual_and_kept(self):
        merged = GitHubService._merge_team_members([{"user_id": "u-old", "role": "member"}], [])
        assert merged == [{"user_id": "u-old", "role": "member", "source": "manual"}]

    def test_a_member_removed_on_github_disappears(self):
        existing = [{"user_id": "u-gone", "role": "member", "source": "github"}]
        assert GitHubService._merge_team_members(existing, []) == []

    def test_the_github_entry_wins_on_overlap(self):
        existing = [{"user_id": "u-1", "role": "member", "source": "github"}]
        merged = GitHubService._merge_team_members(
            existing, [TeamMember(user_id="u-1", role="admin", source="github")]
        )
        assert merged == [{"user_id": "u-1", "role": "admin", "source": "github"}]

    def test_a_manual_member_promoted_on_github_is_not_duplicated(self):
        existing = [{"user_id": "u-1", "role": "member", "source": "manual"}]
        merged = GitHubService._merge_team_members(
            existing, [TeamMember(user_id="u-1", role="admin", source="github")]
        )
        assert merged == [{"user_id": "u-1", "role": "admin", "source": "github"}]


class TestTeamUpsert:
    _ARGS = (
        "GitHub Team: acme/payments",
        "Imported from GitHub Team acme/payments",
        "gh-1",
        "acme",
        4711,
        "payments",
    )

    @pytest.mark.asyncio
    async def test_creates_the_team_with_the_github_identity(self):
        service = _service()
        repo = _team_repo()

        team_id = await service._upsert_team_with_members(
            repo, None, *self._ARGS, [TeamMember(user_id="u-1", source="github")]
        )

        created = repo.create.await_args.args[0]
        assert created.name == "GitHub Team: acme/payments"
        assert created.description == "Imported from GitHub Team acme/payments"
        assert created.github_instance_id == "gh-1"
        assert created.github_org == "acme"
        assert created.github_team_id == 4711
        assert created.github_team_slug == "payments"
        assert team_id == str(created.id)

    @pytest.mark.asyncio
    async def test_creates_nothing_when_no_member_resolved(self):
        service = _service()
        repo = _team_repo()

        assert await service._upsert_team_with_members(repo, None, *self._ARGS, []) is None
        repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_the_update_merges_rather_than_replaces_the_member_list(self):
        service = _service()
        existing = {
            "_id": "t-1",
            "name": "GitHub Team: acme/payments",
            "github_team_id": 4711,
            "members": [
                {"user_id": "u-manual", "role": "admin", "source": "manual"},
                {"user_id": "u-untagged", "role": "member"},
                {"user_id": "u-gone", "role": "member", "source": "github"},
            ],
        }
        repo = _team_repo(existing)

        await service._upsert_team_with_members(
            repo, existing, *self._ARGS, [TeamMember(user_id="u-gh", source="github")]
        )

        assert repo.update.await_args.args[1]["members"] == [
            {"user_id": "u-manual", "role": "admin", "source": "manual"},
            {"user_id": "u-untagged", "role": "member", "source": "manual"},
            {"user_id": "u-gh", "role": "member", "source": "github"},
        ]

    @pytest.mark.asyncio
    async def test_a_renamed_team_keeps_its_name(self):
        service = _service()
        existing = {"_id": "t-1", "name": "Payments Guild", "members": [], "github_team_id": 4711}
        repo = _team_repo(existing)

        await service._upsert_team_with_members(
            repo, existing, *self._ARGS, [TeamMember(user_id="u-1", source="github")]
        )

        assert "name" not in repo.update.await_args.args[1]
        assert "description" not in repo.update.await_args.args[1]

    @pytest.mark.asyncio
    async def test_an_unrenamed_team_follows_a_github_rename(self):
        service = _service()
        existing = {"_id": "t-1", "name": "GitHub Team: acme/pay", "members": [], "github_team_id": 4711}
        repo = _team_repo(existing)

        await service._upsert_team_with_members(
            repo, existing, *self._ARGS, [TeamMember(user_id="u-1", source="github")]
        )

        update = repo.update.await_args.args[1]
        assert update["name"] == "GitHub Team: acme/payments"
        assert update["description"] == "Imported from GitHub Team acme/payments"

    @pytest.mark.asyncio
    async def test_the_slug_is_refreshed_on_every_sync(self):
        service = _service()
        existing = {"_id": "t-1", "name": "Payments Guild", "members": [], "github_team_id": 4711}
        repo = _team_repo(existing)

        await service._upsert_team_with_members(
            repo, existing, *self._ARGS, [TeamMember(user_id="u-1", source="github")]
        )

        assert repo.update.await_args.args[1]["github_team_slug"] == "payments"
