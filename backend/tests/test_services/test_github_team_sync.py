"""GitHub team sync: member resolution, merge semantics and the resolution of a repository to a bound team."""

import asyncio
import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.team import TeamMember
from app.services.github import GitHubService, GitHubTeamRepoAccess, GitHubTeamSyncResult
from tests.mocks.github import make_github_instance

_PERMISSION_LADDER = ["pull", "triage", "push", "maintain", "admin"]

# The organisation listing is the only source of a team's current slug and of its nesting depth.
_PAYMENTS = {"id": 4711, "slug": "payments", "name": "Payments", "parent": None}
_PLATFORM = {"id": 100, "slug": "platform", "name": "Platform", "parent": None}
_ENGINEERING = {"id": 500, "slug": "engineering", "name": "Engineering", "parent": None}
_NESTED = {"id": 900, "slug": "cards", "name": "Cards", "parent": {"id": 500, "slug": "engineering"}}
_ORG_TEAMS = [_PAYMENTS, _PLATFORM, _ENGINEERING, _NESTED]

_ONE_MAINTAINER = [{"login": "ada", "role": "maintainer"}]


def _holds(permission: str = "push") -> GitHubTeamRepoAccess:
    permissions = {
        name: _PERMISSION_LADDER.index(name) <= _PERMISSION_LADDER.index(permission) for name in _PERMISSION_LADDER
    }
    return GitHubTeamRepoAccess(True, {"role_name": permission, "permissions": permissions})


def _service(instance_id: str = "test-github-instance-id") -> GitHubService:
    return GitHubService(make_github_instance(id=instance_id, access_token="ghp-secret"))


def _user_repo(*, by_username=None, by_email=None) -> MagicMock:
    repo = MagicMock()
    repo.get_raw_by_username = AsyncMock(return_value=by_username)
    repo.get_raw_by_email_ci = AsyncMock(return_value=by_email)
    repo.create = AsyncMock()
    return repo


def _bound(doc_id: str, team_id: int, *, slug: str = "payments", name: str = "Payments", members=None) -> dict:
    return {
        "_id": doc_id,
        "name": name,
        "github_instance_id": "test-github-instance-id",
        "github_org": "acme",
        "github_team_id": team_id,
        "github_team_slug": slug,
        "members": members if members is not None else [],
    }


def _team_repo(*bound_teams) -> MagicMock:
    repo = MagicMock()
    repo.find_raw_by_github_org = AsyncMock(return_value=list(bound_teams))
    repo.update = AsyncMock()
    repo.create = AsyncMock()
    return repo


@contextmanager
def _sync_stubs(service, team_repo, *, org_teams=_ORG_TEAMS, access=None, members=_ONE_MAINTAINER, user_repo=None):
    """Stub everything the sync reads: the organisation listing, the per-team checks and the members."""
    answers = access or {}

    async def _check(_org, team_slug, _owner, _repo):
        return answers.get(team_slug, GitHubTeamRepoAccess(False, None))

    stubs = SimpleNamespace(
        checks=AsyncMock(side_effect=_check),
        org_teams=AsyncMock(return_value=org_teams),
        members=AsyncMock(return_value=members),
    )
    with (
        patch.object(service, "get_org_teams", new=stubs.org_teams),
        patch.object(service, "get_team_repository", new=stubs.checks),
        patch.object(service, "get_team_members", new=stubs.members),
        patch("app.services.github.TeamRepository", return_value=team_repo),
        patch("app.services.github.UserRepository", return_value=user_repo or _user_repo(by_username={"_id": "u-1"})),
    ):
        yield stubs


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
        merged = GitHubService._merge_team_members(existing, [TeamMember(user_id="u-1", role="admin", source="github")])
        assert merged == [{"user_id": "u-1", "role": "admin", "source": "github"}]

    def test_a_manual_member_promoted_on_github_is_not_duplicated(self):
        existing = [{"user_id": "u-1", "role": "member", "source": "manual"}]
        merged = GitHubService._merge_team_members(existing, [TeamMember(user_id="u-1", role="admin", source="github")])
        assert merged == [{"user_id": "u-1", "role": "admin", "source": "github"}]


class TestTeamMemberWrite:
    @pytest.mark.asyncio
    async def test_the_write_merges_rather_than_replaces_the_member_list(self):
        service = _service()
        team = _bound(
            "t-1",
            4711,
            members=[
                {"user_id": "u-manual", "role": "admin", "source": "manual"},
                {"user_id": "u-untagged", "role": "member"},
                {"user_id": "u-gone", "role": "member", "source": "github"},
            ],
        )
        repo = _team_repo(team)

        await service._sync_team_members(repo, team, "payments", [TeamMember(user_id="u-gh", source="github")])

        assert repo.update.await_args.args[1]["members"] == [
            {"user_id": "u-manual", "role": "admin", "source": "manual"},
            {"user_id": "u-untagged", "role": "member", "source": "manual"},
            {"user_id": "u-gh", "role": "member", "source": "github"},
        ]

    @pytest.mark.asyncio
    async def test_the_team_keeps_the_name_its_owner_gave_it(self):
        service = _service()
        team = _bound("t-1", 4711, name="Payments Guild")
        repo = _team_repo(team)

        await service._sync_team_members(repo, team, "payments", [TeamMember(user_id="u-1", source="github")])

        update = repo.update.await_args.args[1]
        assert "name" not in update
        assert "description" not in update

    @pytest.mark.asyncio
    async def test_the_slug_is_refreshed_on_every_sync(self):
        service = _service()
        team = _bound("t-1", 4711, slug="pay-old")
        repo = _team_repo(team)

        await service._sync_team_members(repo, team, "payments", [TeamMember(user_id="u-1", source="github")])

        assert repo.update.await_args.args[1]["github_team_slug"] == "payments"


class TestSyncTeamFromGithub:
    @pytest.mark.asyncio
    async def test_an_organisation_with_no_bound_team_costs_no_api_call_and_creates_nothing(self, caplog):
        service = _service()
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, access={"payments": _holds()}) as stubs:
            with caplog.at_level("INFO", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, 0)
        stubs.checks.assert_not_awaited()
        stubs.org_teams.assert_not_awaited()
        team_repo.create.assert_not_called()
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_a_github_team_nobody_bound_is_never_adopted(self, caplog):
        """The cross-cutting groups: their repositories keep the team their owner assigned by hand."""
        service = _service()
        team_repo = _team_repo(_bound("t-platform", 100, slug="platform", name="Platform"))

        with _sync_stubs(service, team_repo, access={"payments": _holds("admin")}) as stubs:
            with caplog.at_level("INFO", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, 0)
        team_repo.create.assert_not_called()
        team_repo.update.assert_not_called()
        # Only the bound team is asked; the holder nobody bound is not even looked at.
        assert [call.args[1] for call in stubs.checks.await_args_list] == ["platform"]
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_the_bound_team_holding_the_repository_wins_and_the_others_do_not_count(self):
        """A team whose check says no would otherwise win here: it carries the lower id."""
        service = _service()
        team_repo = _team_repo(
            _bound("t-platform", 100, slug="platform", name="Platform"),
            _bound("t-pay", 4711),
        )

        with _sync_stubs(service, team_repo, access={"payments": _holds()}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-pay", 1)
        assert stubs.members.await_args.args == ("acme", "payments", 4711)

    @pytest.mark.asyncio
    async def test_the_tiebreak_decides_between_two_holders(self):
        """The shallower team is checked first and carries the lower id, so only depth can unseat it."""
        service = _service()
        team_repo = _team_repo(
            _bound("t-platform", 100, slug="platform", name="Platform"),
            _bound("t-cards", 900, slug="cards", name="Cards"),
        )

        with _sync_stubs(service, team_repo, access={"platform": _holds(), "cards": _holds()}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-cards", 2)
        assert stubs.members.await_args.args == ("acme", "cards", 900)

    @pytest.mark.asyncio
    async def test_the_stronger_permission_wins_between_two_equally_deep_holders(self):
        service = _service()
        team_repo = _team_repo(
            _bound("t-platform", 100, slug="platform", name="Platform"),
            _bound("t-pay", 4711),
        )

        with _sync_stubs(service, team_repo, access={"platform": _holds("pull"), "payments": _holds("admin")}):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-pay", 2)

    @pytest.mark.asyncio
    async def test_a_check_that_went_unanswered_leaves_everything_untouched(self, caplog):
        """Half a candidate list elects a winner the missing answers might have outranked."""
        service = _service()
        team_repo = _team_repo(
            _bound("t-pay", 4711),
            _bound("t-platform", 100, slug="platform", name="Platform"),
        )
        access = {"payments": _holds(), "platform": GitHubTeamRepoAccess(None, None)}

        with _sync_stubs(service, team_repo, access=access) as stubs:
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)
        team_repo.update.assert_not_called()
        stubs.members.assert_not_awaited()
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_an_unreachable_organisation_listing_leaves_everything_untouched(self, caplog):
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711))

        with _sync_stubs(service, team_repo, org_teams=None, access={"payments": _holds()}) as stubs:
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)
        stubs.checks.assert_not_awaited()
        team_repo.update.assert_not_called()
        assert any("acme" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_the_bound_teams_are_read_for_this_instance_and_this_organisation(self):
        service = _service("gh-1")
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo):
            await service.sync_team_from_github(MagicMock(), "acme", "acme-labs/widgets")

        assert team_repo.find_raw_by_github_org.await_args.args == ("gh-1", "acme")

    @pytest.mark.asyncio
    async def test_the_repository_is_addressed_by_its_own_owner_and_the_team_by_the_organisation(self):
        service = _service("gh-1")
        team_repo = _team_repo(_bound("t-pay", 4711))

        with _sync_stubs(service, team_repo, access={"payments": _holds()}) as stubs:
            await service.sync_team_from_github(MagicMock(), "acme", "acme-labs/widgets")

        assert stubs.checks.await_args.args == ("acme", "payments", "acme-labs", "widgets")
        assert stubs.org_teams.await_args.args == ("acme",)
        assert stubs.members.await_args.args == ("acme", "payments", 4711)

    @pytest.mark.asyncio
    async def test_a_renamed_team_is_addressed_by_the_slug_the_organisation_reports(self):
        """The binding is the team number; a stored slug would address whoever took the old one."""
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711, slug="pay-old"))

        with _sync_stubs(service, team_repo, access={"payments": _holds()}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-pay", 1)
        assert stubs.checks.await_args.args[1] == "payments"
        assert team_repo.update.await_args.args[1]["github_team_slug"] == "payments"

    @pytest.mark.asyncio
    async def test_a_binding_the_organisation_no_longer_lists_leaves_everything_untouched(self, caplog):
        service = _service()
        team_repo = _team_repo(_bound("t-gone", 6666, slug="dissolved", name="Dissolved"))

        with _sync_stubs(service, team_repo) as stubs:
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)
        stubs.checks.assert_not_awaited()
        team_repo.update.assert_not_called()
        assert any("6666" in record.getMessage() for record in caplog.records if record.levelname == "WARNING")

    @pytest.mark.asyncio
    async def test_a_bound_team_the_listing_hides_never_hands_the_repository_to_a_visible_one(self):
        """A secret team is absent from the organisation listing. Skipping it elected whichever
        team did answer and reported one candidate — a confident wrong answer."""
        service = _service()
        team_repo = _team_repo(
            _bound("t-hidden", 900, slug="cards", name="Cards"),
            _bound("t-visible", 100, slug="platform", name="Platform"),
        )
        visible_only = [team for team in _ORG_TEAMS if team["id"] != 900]
        access = {"cards": _holds(), "platform": _holds()}

        with _sync_stubs(service, team_repo, org_teams=visible_only, access=access):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)
        team_repo.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_binding_carrying_no_team_number_is_undetermined_rather_than_ignored(self):
        """The repository query filters these out; reaching the sync means the filter stopped working."""
        service = _service()
        unnumbered = _bound("t-halfway", 4711)
        unnumbered["github_team_id"] = None
        team_repo = _team_repo(unnumbered)

        with _sync_stubs(service, team_repo, access={"payments": _holds()}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)
        stubs.checks.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_holders_and_the_winner_are_logged(self, caplog):
        service = _service()
        team_repo = _team_repo(
            _bound("t-pay", 4711),
            _bound("t-platform", 100, slug="platform", name="Platform"),
        )

        with _sync_stubs(service, team_repo, access={"payments": _holds("admin"), "platform": _holds("pull")}):
            with caplog.at_level("INFO", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result.candidate_count == 2
        logged = " ".join(record.getMessage() for record in caplog.records)
        assert "payments" in logged
        assert "platform" in logged

    @pytest.mark.asyncio
    async def test_an_unreachable_member_list_keeps_the_existing_team(self):
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711))

        with _sync_stubs(service, team_repo, access={"payments": _holds()}, members=None):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-pay", 1)
        team_repo.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_members_that_all_fail_to_resolve_leave_the_stored_members_untouched(self, caplog):
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711, members=[{"user_id": "u-1", "role": "admin", "source": "github"}]))
        members = [{"login": "ada", "role": "maintainer"}, {"login": "bob", "role": "member"}]

        with _sync_stubs(service, team_repo, access={"payments": _holds()}, members=members, user_repo=_user_repo()):
            with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
                with caplog.at_level("WARNING", logger="app.services.github"):
                    result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-pay", 1)
        team_repo.update.assert_not_called()
        warnings = " ".join(record.getMessage() for record in caplog.records if record.levelname == "WARNING")
        assert "0 of 2" in warnings
        # A refused profile lookup and a hidden email are the same None here, so the line reports an
        # outcome: blaming user provisioning misdirects the operator in exactly the 403 case.
        assert "no local account" not in warnings

    @pytest.mark.asyncio
    async def test_a_member_that_does_not_resolve_never_blocks_the_ones_that_do(self):
        """The routine case: a bot resolves to nobody while a real member does."""
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711))
        user_repo = MagicMock()
        user_repo.get_raw_by_username = AsyncMock(side_effect=[None, {"_id": "u-1"}])
        user_repo.get_raw_by_email_ci = AsyncMock(return_value=None)
        members = [{"login": "dependabot", "role": "member"}, {"login": "ada", "role": "maintainer"}]

        with _sync_stubs(service, team_repo, access={"payments": _holds()}, members=members, user_repo=user_repo):
            with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-pay", 1)
        assert team_repo.update.await_args.args[1]["members"] == [
            {"user_id": "u-1", "role": "admin", "source": "github"}
        ]

    @pytest.mark.asyncio
    async def test_a_team_nobody_is_left_in_still_empties_the_github_subset(self):
        service = _service()
        team_repo = _team_repo(
            _bound(
                "t-pay",
                4711,
                members=[
                    {"user_id": "u-1", "role": "admin", "source": "github"},
                    {"user_id": "u-manual", "role": "member", "source": "manual"},
                ],
            )
        )

        with _sync_stubs(service, team_repo, access={"payments": _holds()}, members=[]):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult("t-pay", 1)
        assert team_repo.update.await_args.args[1]["members"] == [
            {"user_id": "u-manual", "role": "member", "source": "manual"}
        ]

    @pytest.mark.asyncio
    async def test_a_manual_member_of_the_bound_team_survives_the_sync(self):
        service = _service()
        team_repo = _team_repo(
            _bound("t-pay", 4711, members=[{"user_id": "u-manual", "role": "admin", "source": "manual"}])
        )

        with _sync_stubs(service, team_repo, access={"payments": _holds()}):
            await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert team_repo.update.await_args.args[1]["members"] == [
            {"user_id": "u-manual", "role": "admin", "source": "manual"},
            {"user_id": "u-1", "role": "admin", "source": "github"},
        ]

    @pytest.mark.asyncio
    async def test_an_exception_is_swallowed_and_reports_nothing_determined(self):
        service = _service()
        team_repo = _team_repo()
        team_repo.find_raw_by_github_org = AsyncMock(side_effect=RuntimeError("boom"))

        with patch("app.services.github.TeamRepository", return_value=team_repo):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None, None)


class TestResolutionCost:
    """The checks run inside the ingest request, so their cost is the request's."""

    _SLOW_CHECK = 0.05

    @staticmethod
    def _many_bound_teams(count: int):
        org_teams = [{"id": 1000 + index, "slug": f"t{index}", "parent": None} for index in range(count)]
        bound = [_bound(f"t-{index}", 1000 + index, slug=f"t{index}", name=f"T{index}") for index in range(count)]
        return org_teams, bound

    @pytest.mark.asyncio
    async def test_the_checks_do_not_add_up(self):
        """Ten bound teams against a slow GitHub cost one check, not ten."""
        count = 10
        org_teams, bound = self._many_bound_teams(count)
        service = _service()

        async def _slow_check(_org, _slug, _owner, _repo):
            await asyncio.sleep(self._SLOW_CHECK)
            return GitHubTeamRepoAccess(False, None)

        with _sync_stubs(service, _team_repo(*bound), org_teams=org_teams) as stubs:
            stubs.checks.side_effect = _slow_check
            started = time.perf_counter()
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")
            elapsed = time.perf_counter() - started

        assert result == GitHubTeamSyncResult(None, 0)
        assert stubs.checks.await_count == count
        assert elapsed < self._SLOW_CHECK * count / 2

    @pytest.mark.asyncio
    async def test_a_github_that_never_answers_bounds_the_ingest_and_stays_undetermined(self, caplog):
        service = _service()
        org_teams, bound = self._many_bound_teams(2)

        async def _never_answers(*_args, **_kwargs):
            await asyncio.sleep(60)
            raise AssertionError("the resolution step should have been abandoned")

        with _sync_stubs(service, _team_repo(*bound), org_teams=org_teams) as stubs:
            stubs.checks.side_effect = _never_answers
            with patch("app.services.github._GITHUB_RESOLUTION_TIMEOUT", 0.05):
                with caplog.at_level("WARNING", logger="app.services.github"):
                    started = time.perf_counter()
                    result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")
                    elapsed = time.perf_counter() - started

        assert result == GitHubTeamSyncResult(None, None)
        assert elapsed < 1
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)
