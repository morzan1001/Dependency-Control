"""GitHub team sync: member resolution, merge semantics and the sync itself."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.team import TeamMember
from app.services.github import GitHubService, GitHubTeamSyncResult
from tests.mocks.github import make_github_instance

_WINNER = {"id": 4711, "slug": "payments", "name": "Payments", "permission": "push", "parent": None}
_RUNNER_UP = {"id": 9000, "slug": "platform", "name": "Platform", "permission": "pull", "parent": None}

# Equal on every rule but depth, and the lower id is the shallower team so the id tiebreak
# disagrees with the depth rule.
_SHALLOW = {"id": 100, "slug": "platform", "name": "Platform", "parent": None}
_NESTED = {"id": 900, "slug": "payments", "name": "Payments", "parent": {"id": 500, "slug": "engineering"}}
# The grandparent holds no access to the repository, so it appears only in the organisation listing.
_NESTED_PARENT = {"id": 500, "slug": "engineering", "name": "Engineering", "parent": None}


def _service(instance_id: str = "test-github-instance-id") -> GitHubService:
    return GitHubService(make_github_instance(id=instance_id, access_token="ghp-secret"))


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


def _stub_reads(service, *, repo_teams, org_teams=None, members=None):
    return (
        patch.object(service, "get_repository_teams", new=AsyncMock(return_value=repo_teams)),
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=org_teams or [])),
        patch.object(service, "get_team_members", new=AsyncMock(return_value=members)),
    )


class TestMemberResolution:
    @pytest.mark.asyncio
    async def test_the_login_is_matched_against_the_username_first(self):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1", "username": "ada"})

        with patch.object(service, "get_user_public_email", new=AsyncMock()) as public_email:
            members, _ = await service._build_team_members([{"login": "ada", "role": "member"}], repo)

        assert [m.user_id for m in members] == ["u-1"]
        public_email.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_public_profile_email_is_the_fallback_and_is_case_insensitive(self):
        service = _service()
        repo = _user_repo(by_username=None, by_email={"_id": "u-2", "email": "ada@corp.com"})

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value="Ada@Corp.com")):
            members, _ = await service._build_team_members([{"login": "ada-l", "role": "member"}], repo)

        assert [m.user_id for m in members] == ["u-2"]
        repo.get_raw_by_email_ci.assert_awaited_once_with("Ada@Corp.com")

    @pytest.mark.asyncio
    async def test_a_hidden_profile_email_is_never_looked_up(self):
        service = _service()
        repo = _user_repo()

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
            assert await service._build_team_members([{"login": "ada", "role": "member"}], repo) == ([], 1)

        repo.get_raw_by_email_ci.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_member_with_no_local_account_is_skipped_and_not_created(self, caplog):
        service = _service()
        repo = _user_repo()

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
            with caplog.at_level("DEBUG", logger="app.services.github"):
                members, _ = await service._build_team_members([{"login": "dependabot", "role": "member"}], repo)

        assert members == []
        repo.create.assert_not_called()
        assert any("dependabot" in record.getMessage() for record in caplog.records if record.levelname == "DEBUG")

    @pytest.mark.asyncio
    async def test_every_resolved_member_is_tagged_github(self):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})
        members, _ = await service._build_team_members([{"login": "ada", "role": "member"}], repo)
        assert members[0].source == "github"

    @pytest.mark.asyncio
    async def test_two_logins_resolving_to_one_user_yield_a_single_member(self):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})

        members, _ = await service._build_team_members(
            [{"login": "ada", "role": "maintainer"}, {"login": "ada-work", "role": "member"}], repo
        )

        assert members == [TeamMember(user_id="u-1", role="admin", source="github")]

    @pytest.mark.asyncio
    async def test_the_stronger_role_wins_whichever_login_comes_first(self):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})

        members, _ = await service._build_team_members(
            [{"login": "ada-work", "role": "member"}, {"login": "ada", "role": "maintainer"}], repo
        )

        assert members == [TeamMember(user_id="u-1", role="admin", source="github")]

    @pytest.mark.asyncio
    async def test_a_deduplicated_login_does_not_count_as_unresolved(self):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})

        _, unresolved = await service._build_team_members(
            [{"login": "ada", "role": "maintainer"}, {"login": "ada-work", "role": "member"}], repo
        )

        assert unresolved == 0

    @pytest.mark.asyncio
    async def test_the_unresolved_count_is_returned_for_the_caller_to_act_on(self):
        service = _service()
        repo = _user_repo()
        github_members = [{"login": f"bot-{index}", "role": "member"} for index in range(3)]

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
            assert await service._build_team_members(github_members, repo) == ([], 3)

    @pytest.mark.asyncio
    async def test_the_bots_every_organisation_has_count_without_costing_the_real_members(self):
        service = _service()
        repo = MagicMock()
        repo.get_raw_by_username = AsyncMock(side_effect=[None, None, {"_id": "u-1"}])
        repo.get_raw_by_email_ci = AsyncMock(return_value=None)
        github_members = [
            {"login": "dependabot", "role": "member"},
            {"login": "renovate", "role": "member"},
            {"login": "ada", "role": "member"},
        ]

        with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
            members, unresolved = await service._build_team_members(github_members, repo)

        assert [m.user_id for m in members] == ["u-1"]
        assert unresolved == 2


class TestRoleMapping:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("github_role", "expected"), [("maintainer", "admin"), ("member", "member")])
    async def test_maintainer_becomes_admin(self, github_role, expected):
        service = _service()
        repo = _user_repo(by_username={"_id": "u-1"})
        members, _ = await service._build_team_members([{"login": "ada", "role": github_role}], repo)
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


class TestSyncTeamFromGithub:
    @pytest.mark.asyncio
    async def test_no_candidate_team_leaves_the_project_alone(self, caplog):
        service = _service()
        repo_reads, org_reads, member_reads = _stub_reads(service, repo_teams=[])

        with repo_reads, org_reads, member_reads, caplog.at_level("INFO", logger="app.services.github"):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, 0)
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_an_unreachable_api_reports_an_undetermined_count(self):
        service = _service()
        repo_reads, org_reads, member_reads = _stub_reads(service, repo_teams=None)

        with repo_reads, org_reads, member_reads:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)

    @pytest.mark.asyncio
    async def test_the_candidate_count_and_the_winner_are_logged(self, caplog):
        service = _service()
        repo_reads, org_reads, member_reads = _stub_reads(
            service, repo_teams=[_RUNNER_UP, _WINNER], members=[{"login": "ada", "role": "maintainer"}]
        )
        resolved = ([TeamMember(user_id="u-1", role="admin", source="github")], 0)

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch.object(service, "_build_team_members", new=AsyncMock(return_value=resolved)),
            patch("app.services.github.TeamRepository", return_value=_team_repo()),
            patch("app.services.github.UserRepository", return_value=_user_repo()),
            caplog.at_level("INFO", logger="app.services.github"),
        ):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result.candidate_count == 2
        logged = " ".join(record.getMessage() for record in caplog.records)
        assert "payments" in logged
        assert "platform" in logged

    @pytest.mark.asyncio
    async def test_a_candidate_with_no_slug_does_not_take_the_repository_down_with_it(self):
        """It outranks the sound team on permission, so an unguarded read of its slug aborts the sync."""
        service = _service()
        unaddressable = {"id": 1, "name": "Broken", "permission": "admin", "parent": None}
        repo_reads, org_reads, member_reads = _stub_reads(
            service, repo_teams=[unaddressable, _WINNER], members=[{"login": "ada", "role": "maintainer"}]
        )

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch("app.services.github.TeamRepository", return_value=_team_repo()),
            patch("app.services.github.UserRepository", return_value=_user_repo(by_username={"_id": "u-1"})),
        ):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")
            member_read = service.get_team_members.await_args

        assert result.team_id is not None
        assert result.candidate_count == 2
        assert member_read.args == ("acme", "payments", 4711)

    @pytest.mark.asyncio
    async def test_the_organisation_map_is_what_lets_the_nested_team_win(self):
        service = _service()
        repo_reads, org_reads, member_reads = _stub_reads(
            service,
            repo_teams=[_SHALLOW, _NESTED],
            org_teams=[_SHALLOW, _NESTED_PARENT, _NESTED],
            members=[{"login": "ada", "role": "maintainer"}],
        )

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch("app.services.github.TeamRepository", return_value=_team_repo()),
            patch("app.services.github.UserRepository", return_value=_user_repo(by_username={"_id": "u-1"})),
        ):
            await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")
            member_read = service.get_team_members.await_args

        # Depth is only computable from the organisation listing: the repository endpoint gives the
        # nested team a parent that is not itself among the candidates.
        assert member_read.args == ("acme", "payments", 900)

    @pytest.mark.asyncio
    async def test_each_read_is_scoped_to_the_repository_owner_the_org_and_the_instance(self):
        service = _service("gh-1")
        team_repo = _team_repo()
        repo_reads, org_reads, member_reads = _stub_reads(
            service, repo_teams=[_WINNER], members=[{"login": "ada", "role": "maintainer"}]
        )

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch("app.services.github.TeamRepository", return_value=team_repo),
            patch("app.services.github.UserRepository", return_value=_user_repo(by_username={"_id": "u-1"})),
        ):
            await service.sync_team_from_github(MagicMock(), "acme", "acme-labs/widgets")
            repository_read = service.get_repository_teams.await_args
            org_read = service.get_org_teams.await_args
            member_read = service.get_team_members.await_args

        # The repository is addressed by its own owner; teams are addressed by the organisation.
        assert repository_read.args == ("acme-labs", "widgets")
        assert org_read.args == ("acme",)
        assert member_read.args == ("acme", "payments", 4711)
        assert team_repo.get_raw_by_github_team.await_args.args == ("gh-1", 4711)

    @pytest.mark.asyncio
    async def test_an_unreachable_member_list_keeps_the_existing_team(self):
        service = _service()
        existing = {"_id": "t-1", "name": "GitHub Team: acme/payments", "members": [], "github_team_id": 4711}
        repo_reads, org_reads, member_reads = _stub_reads(service, repo_teams=[_WINNER], members=None)

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch("app.services.github.TeamRepository", return_value=_team_repo(existing)),
            patch("app.services.github.UserRepository", return_value=_user_repo()),
        ):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-1", 1)

    @pytest.mark.asyncio
    async def test_members_that_all_fail_to_resolve_leave_the_stored_members_untouched(self, caplog):
        service = _service()
        existing = {
            "_id": "t-1",
            "name": "GitHub Team: acme/payments",
            "github_team_id": 4711,
            "members": [{"user_id": "u-1", "role": "admin", "source": "github"}],
        }
        team_repo = _team_repo(existing)
        repo_reads, org_reads, member_reads = _stub_reads(
            service,
            repo_teams=[_WINNER],
            members=[{"login": "ada", "role": "maintainer"}, {"login": "bob", "role": "member"}],
        )

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)),
            patch("app.services.github.TeamRepository", return_value=team_repo),
            patch("app.services.github.UserRepository", return_value=_user_repo()),
            caplog.at_level("WARNING", logger="app.services.github"),
        ):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-1", 1)
        team_repo.update.assert_not_called()
        warnings = " ".join(record.getMessage() for record in caplog.records if record.levelname == "WARNING")
        assert "0 of 2" in warnings

    @pytest.mark.asyncio
    async def test_a_member_that_does_not_resolve_never_blocks_the_ones_that_do(self):
        """The routine case: a bot resolves to nobody while a real member does."""
        service = _service()
        existing = {"_id": "t-1", "name": "GitHub Team: acme/payments", "github_team_id": 4711, "members": []}
        team_repo = _team_repo(existing)
        user_repo = MagicMock()
        user_repo.get_raw_by_username = AsyncMock(side_effect=[None, {"_id": "u-1"}])
        user_repo.get_raw_by_email_ci = AsyncMock(return_value=None)
        repo_reads, org_reads, member_reads = _stub_reads(
            service,
            repo_teams=[_WINNER],
            members=[{"login": "dependabot", "role": "member"}, {"login": "ada", "role": "maintainer"}],
        )

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)),
            patch("app.services.github.TeamRepository", return_value=team_repo),
            patch("app.services.github.UserRepository", return_value=user_repo),
        ):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-1", 1)
        assert team_repo.update.await_args.args[1]["members"] == [
            {"user_id": "u-1", "role": "admin", "source": "github"}
        ]

    @pytest.mark.asyncio
    async def test_a_team_nobody_is_left_in_still_empties_the_github_subset(self):
        service = _service()
        existing = {
            "_id": "t-1",
            "name": "GitHub Team: acme/payments",
            "github_team_id": 4711,
            "members": [
                {"user_id": "u-1", "role": "admin", "source": "github"},
                {"user_id": "u-manual", "role": "member", "source": "manual"},
            ],
        }
        team_repo = _team_repo(existing)
        repo_reads, org_reads, member_reads = _stub_reads(service, repo_teams=[_WINNER], members=[])

        with (
            repo_reads,
            org_reads,
            member_reads,
            patch("app.services.github.TeamRepository", return_value=team_repo),
            patch("app.services.github.UserRepository", return_value=_user_repo()),
        ):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-1", 1)
        assert team_repo.update.await_args.args[1]["members"] == [
            {"user_id": "u-manual", "role": "member", "source": "manual"}
        ]

    @pytest.mark.asyncio
    async def test_an_exception_is_swallowed_and_reports_nothing_determined(self):
        service = _service()
        with patch.object(service, "get_repository_teams", new=AsyncMock(side_effect=RuntimeError("boom"))):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)
