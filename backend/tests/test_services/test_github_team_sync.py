"""GitHub team sync: member resolution, merge semantics, and resolving a repository to the teams holding it."""

import asyncio
import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pymongo.errors import DuplicateKeyError

from app.models.team import GitHubTeamBinding, Team, TeamMember
from app.services.github import GitHubService, GitHubTeamSyncResult, _RepositoryHolder
from tests.mocks.github import make_github_instance

# The organisation listing is the only source of a team's current slug.
_PAYMENTS = {"id": 4711, "slug": "payments", "name": "Payments", "parent": None}
_PLATFORM = {"id": 100, "slug": "platform", "name": "Platform", "parent": None}
_ENGINEERING = {"id": 500, "slug": "engineering", "name": "Engineering", "parent": None}
_NESTED = {"id": 900, "slug": "cards", "name": "Cards", "parent": {"id": 500, "slug": "engineering"}}
_ORG_TEAMS = [_PAYMENTS, _PLATFORM, _ENGINEERING, _NESTED]

_ONE_MAINTAINER = [{"login": "ada", "role": "maintainer"}]

# The organisation map, in the shape the walk leaves behind: repository full name -> holding teams.
_NO_HOLDERS: dict[str, list[int]] = {}
_HELD_BY_PLATFORM = {"acme/widgets": [100]}


def _service(instance_id: str = "test-github-instance-id", *, sync_teams: bool = False) -> GitHubService:
    return GitHubService(make_github_instance(id=instance_id, access_token="ghp-secret", sync_teams=sync_teams))


def _user_repo(*, by_username=None, by_email=None) -> MagicMock:
    repo = MagicMock()
    repo.get_raw_by_username = AsyncMock(return_value=by_username)
    repo.get_raw_by_email_ci = AsyncMock(return_value=by_email)
    repo.create = AsyncMock()
    return repo


def _bound(
    doc_id: str,
    team_id: int,
    *,
    slug: str = "payments",
    name: str = "Payments",
    members=None,
    instance_id: str = "test-github-instance-id",
) -> dict:
    return {
        "_id": doc_id,
        "name": name,
        "bindings": [
            GitHubTeamBinding(instance_id=instance_id, org="acme", external_id=team_id, slug=slug).model_dump()
        ],
        "members": members if members is not None else [],
    }


def _team_repo(*bound_teams, adopted=None, unbound=None) -> MagicMock:
    repo = MagicMock()
    repo.find_raw_by_github_org = AsyncMock(return_value=list(bound_teams))
    repo.get_raw_by_binding = AsyncMock(return_value=adopted)
    unbound_teams = list(unbound or [])

    async def _bind(team_id, binding):
        team = next(team for team in unbound_teams if team["_id"] == team_id)
        return {**team, "bindings": [*(team.get("bindings") or []), binding]}

    repo.find_raw_unbound_for_instance = AsyncMock(return_value=unbound_teams)
    repo.add_binding_if_absent = AsyncMock(side_effect=_bind)
    repo.update_with_binding = AsyncMock()
    repo.create = AsyncMock()
    return repo


@contextmanager
def _sync_stubs(
    service,
    team_repo,
    *,
    org_teams=_ORG_TEAMS,
    access=None,
    members=_ONE_MAINTAINER,
    user_repo=None,
    repo_map=_NO_HOLDERS,
):
    """Stub everything the sync reads: the organisation listing and map, the checks and the members."""
    answers = access or {}

    async def _check(_org, team_slug, _owner, _repo):
        return answers.get(team_slug, False)

    stubs = SimpleNamespace(
        checks=AsyncMock(side_effect=_check),
        org_teams=AsyncMock(return_value=org_teams),
        members=AsyncMock(return_value=members),
        repo_map=AsyncMock(return_value=repo_map),
    )
    with (
        patch.object(service, "get_org_teams", new=stubs.org_teams),
        patch.object(service, "get_team_repository", new=stubs.checks),
        patch.object(service, "get_team_members", new=stubs.members),
        patch.object(service, "get_org_repository_map", new=stubs.repo_map),
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

        await service._refresh_team(
            repo, "acme", _RepositoryHolder(team, 4711, "payments"), [TeamMember(user_id="u-gh", source="github")])

        assert repo.update_with_binding.await_args.args[1]["members"] == [
            {"user_id": "u-manual", "role": "admin", "source": "manual"},
            {"user_id": "u-untagged", "role": "member", "source": "manual"},
            {"user_id": "u-gh", "role": "member", "source": "github"},
        ]

    @pytest.mark.asyncio
    async def test_the_team_keeps_the_name_its_owner_gave_it(self):
        service = _service()
        team = _bound("t-1", 4711, name="Payments Guild")
        repo = _team_repo(team)

        await service._refresh_team(
            repo, "acme", _RepositoryHolder(team, 4711, "payments"), [TeamMember(user_id="u-1", source="github")])

        update = repo.update_with_binding.await_args.args[1]
        assert "name" not in update
        assert "description" not in update

    @pytest.mark.asyncio
    async def test_a_team_still_carrying_the_generated_name_follows_the_slug(self):
        service = _service()
        team = _bound("t-1", 4711, slug="pay-old", name="GitHub Team: acme/pay-old")
        repo = _team_repo(team)

        await service._refresh_team(
            repo, "acme", _RepositoryHolder(team, 4711, "payments"), [TeamMember(user_id="u-1", source="github")])

        update = repo.update_with_binding.await_args.args[1]
        assert update["name"] == "GitHub Team: acme/payments"
        assert update["description"] == "Imported from GitHub team acme/payments"

    @pytest.mark.asyncio
    async def test_a_generated_name_that_already_matches_is_not_rewritten(self):
        service = _service()
        team = _bound("t-1", 4711, name="GitHub Team: acme/payments")
        repo = _team_repo(team)

        await service._refresh_team(
            repo, "acme", _RepositoryHolder(team, 4711, "payments"), [TeamMember(user_id="u-1", source="github")])

        assert "name" not in repo.update_with_binding.await_args.args[1]

    @pytest.mark.asyncio
    async def test_the_stored_slug_follows_the_one_the_organisation_reports(self):
        service = _service()
        team = _bound("t-1", 4711, slug="pay-old")
        repo = _team_repo(team)

        await service._refresh_team(
            repo, "acme", _RepositoryHolder(team, 4711, "payments"), [TeamMember(user_id="u-1", source="github")])

        assert repo.update_with_binding.await_args.args[3] == {"slug": "payments"}

    @pytest.mark.asyncio
    async def test_a_rename_is_written_even_when_no_member_could_be_read(self):
        """Barely a login resolves here, so a rename tied to a member write would never happen."""
        service = _service()
        team = _bound("t-1", 4711, slug="pay-old", name="GitHub Team: acme/pay-old")
        repo = _team_repo(team)

        await service._refresh_team(
            repo, "acme", _RepositoryHolder(team, 4711, "payments"), None)

        update = repo.update_with_binding.await_args.args[1]
        assert update["name"] == "GitHub Team: acme/payments"
        assert "members" not in update

    @pytest.mark.asyncio
    async def test_a_team_nothing_changed_about_is_not_written_at_all(self):
        service = _service()
        team = _bound("t-1", 4711)
        repo = _team_repo(team)

        await service._refresh_team(
            repo, "acme", _RepositoryHolder(team, 4711, "payments"), None)

        repo.update_with_binding.assert_not_called()


class TestSyncTeamFromGithub:
    @pytest.mark.asyncio
    async def test_an_organisation_with_no_bound_team_and_no_creation_costs_no_api_call(self, caplog):
        service = _service()
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, access={"payments": True}) as stubs:
            with caplog.at_level("INFO", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult([])
        stubs.checks.assert_not_awaited()
        stubs.org_teams.assert_not_awaited()
        stubs.repo_map.assert_not_awaited()
        team_repo.create.assert_not_called()
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_a_group_granted_access_later_is_found_although_a_bound_team_already_holds_it(self):
        """Stopping at the first answer froze the owners of a repository at whoever held it first;
        a sync has to converge on who holds it now."""
        service = _service(sync_teams=True)
        team_repo = _team_repo(_bound("t-pay", 4711))

        with _sync_stubs(service, team_repo, access={"payments": True}, repo_map=_HELD_BY_PLATFORM) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = team_repo.create.await_args.args[0]
        assert created.name == "GitHub Team: acme/platform"
        assert result == GitHubTeamSyncResult(["t-pay", str(created.id)])
        stubs.repo_map.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_only_the_bound_teams_that_hold_the_repository_are_attached(self):
        service = _service()
        team_repo = _team_repo(
            _bound("t-platform", 100, slug="platform", name="Platform"),
            _bound("t-pay", 4711),
        )

        with _sync_stubs(service, team_repo, access={"payments": True}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-pay"])
        assert stubs.members.await_args.args == ("acme", "payments", 4711)

    @pytest.mark.asyncio
    async def test_every_holder_owns_the_repository_rather_than_the_best_of_them(self):
        """Ranking them handed the project to one team and hid it from the people in the others,
        who work on the very same repository."""
        service = _service()
        team_repo = _team_repo(
            _bound("t-platform", 100, slug="platform", name="Platform"),
            _bound("t-cards", 900, slug="cards", name="Cards"),
        )

        with _sync_stubs(service, team_repo, access={"platform": True, "cards": True}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-platform", "t-cards"])
        # Ownership grants access through membership, so every attached team's is refreshed.
        assert [call.args[1] for call in stubs.members.await_args_list] == ["platform", "cards"]

    @pytest.mark.asyncio
    async def test_a_holder_whose_members_cannot_be_read_still_owns_the_repository(self):
        """Member sync is best effort; the holder check is what decides ownership."""
        service = _service()
        team_repo = _team_repo(
            _bound("t-platform", 100, slug="platform", name="Platform"),
            _bound("t-pay", 4711),
        )

        async def _members(_org, slug, _team_id):
            return None if slug == "platform" else _ONE_MAINTAINER

        with _sync_stubs(service, team_repo, access={"platform": True, "payments": True}) as stubs:
            stubs.members.side_effect = _members
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-platform", "t-pay"])
        assert [call.args[0] for call in team_repo.update_with_binding.await_args_list] == ["t-pay"]

    @pytest.mark.asyncio
    async def test_a_check_that_went_unanswered_leaves_everything_untouched(self, caplog):
        """Half a candidate list elects a winner the missing answers might have outranked."""
        service = _service()
        team_repo = _team_repo(
            _bound("t-pay", 4711),
            _bound("t-platform", 100, slug="platform", name="Platform"),
        )
        access = {"payments": True, "platform": None}

        with _sync_stubs(service, team_repo, access=access) as stubs:
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None)
        team_repo.update_with_binding.assert_not_called()
        stubs.members.assert_not_awaited()
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_an_unreachable_organisation_listing_leaves_everything_untouched(self, caplog):
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711))

        with _sync_stubs(service, team_repo, org_teams=None, access={"payments": True}) as stubs:
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None)
        stubs.checks.assert_not_awaited()
        team_repo.update_with_binding.assert_not_called()
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
        team_repo = _team_repo(_bound("t-pay", 4711, instance_id="gh-1"))

        with _sync_stubs(service, team_repo, access={"payments": True}) as stubs:
            await service.sync_team_from_github(MagicMock(), "acme", "acme-labs/widgets")

        assert stubs.checks.await_args.args == ("acme", "payments", "acme-labs", "widgets")
        assert stubs.org_teams.await_args.args == ("acme",)
        assert stubs.members.await_args.args == ("acme", "payments", 4711)

    @pytest.mark.asyncio
    async def test_a_renamed_team_is_addressed_by_the_slug_the_organisation_reports(self):
        """The binding is the team number; a stored slug would address whoever took the old one."""
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711, slug="pay-old"))

        with _sync_stubs(service, team_repo, access={"payments": True}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-pay"])
        assert stubs.checks.await_args.args[1] == "payments"
        assert team_repo.update_with_binding.await_args.args[3] == {"slug": "payments"}

    @pytest.mark.asyncio
    async def test_a_binding_the_organisation_no_longer_lists_leaves_everything_untouched(self, caplog):
        service = _service()
        team_repo = _team_repo(_bound("t-gone", 6666, slug="dissolved", name="Dissolved"))

        with _sync_stubs(service, team_repo) as stubs:
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None)
        stubs.checks.assert_not_awaited()
        team_repo.update_with_binding.assert_not_called()
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
        access = {"cards": True, "platform": True}

        with _sync_stubs(service, team_repo, org_teams=visible_only, access=access):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None)
        team_repo.update_with_binding.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_binding_of_another_instance_is_undetermined_rather_than_ignored(self):
        """Resolution asks each bound team through the binding of THIS instance. A team the query
        should never have returned has none, and skipping it would hand the repository to whoever
        did answer and report that as determined."""
        service = _service()
        team_repo = _team_repo(_bound("t-elsewhere", 4711, instance_id="gh-other"))

        with _sync_stubs(service, team_repo, access={"payments": True}) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None)
        stubs.checks.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_every_holder_is_logged(self, caplog):
        service = _service()
        team_repo = _team_repo(
            _bound("t-pay", 4711),
            _bound("t-platform", 100, slug="platform", name="Platform"),
        )

        with _sync_stubs(service, team_repo, access={"payments": True, "platform": True}):
            with caplog.at_level("INFO", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result.team_ids == ["t-pay", "t-platform"]
        logged = " ".join(record.getMessage() for record in caplog.records)
        assert "payments" in logged
        assert "platform" in logged

    @pytest.mark.asyncio
    async def test_an_unreachable_member_list_keeps_the_existing_team(self):
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711))

        with _sync_stubs(service, team_repo, access={"payments": True}, members=None):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-pay"])
        team_repo.update_with_binding.assert_not_called()

    @pytest.mark.asyncio
    async def test_members_that_all_fail_to_resolve_leave_the_stored_members_untouched(self, caplog):
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711, members=[{"user_id": "u-1", "role": "admin", "source": "github"}]))
        members = [{"login": "ada", "role": "maintainer"}, {"login": "bob", "role": "member"}]

        with _sync_stubs(service, team_repo, access={"payments": True}, members=members, user_repo=_user_repo()):
            with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
                with caplog.at_level("WARNING", logger="app.services.github"):
                    result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-pay"])
        team_repo.update_with_binding.assert_not_called()
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

        with _sync_stubs(service, team_repo, access={"payments": True}, members=members, user_repo=user_repo):
            with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-pay"])
        assert team_repo.update_with_binding.await_args.args[1]["members"] == [
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

        with _sync_stubs(service, team_repo, access={"payments": True}, members=[]):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-pay"])
        assert team_repo.update_with_binding.await_args.args[1]["members"] == [
            {"user_id": "u-manual", "role": "member", "source": "manual"}
        ]

    @pytest.mark.asyncio
    async def test_a_manual_member_of_the_bound_team_survives_the_sync(self):
        service = _service()
        team_repo = _team_repo(
            _bound("t-pay", 4711, members=[{"user_id": "u-manual", "role": "admin", "source": "manual"}])
        )

        with _sync_stubs(service, team_repo, access={"payments": True}):
            await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert team_repo.update_with_binding.await_args.args[1]["members"] == [
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

        assert result == GitHubTeamSyncResult(None)


class TestTeamCreation:
    """A GitHub group nobody bound becomes a team, the way a GitLab group does."""

    @staticmethod
    def _created(team_repo) -> Team:
        return team_repo.create.await_args.args[0]

    @pytest.mark.asyncio
    async def test_a_group_nobody_bound_becomes_a_team_and_owns_the_repository(self, caplog):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM):
            with caplog.at_level("INFO", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = self._created(team_repo)
        assert created.name == "GitHub Team: acme/platform"
        assert result == GitHubTeamSyncResult([str(created.id)])
        assert any("GitHub Team: acme/platform" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_the_new_team_carries_the_binding_that_makes_it_a_candidate_from_then_on(self):
        service = _service("gh-1", sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM):
            await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = self._created(team_repo)
        assert [binding.model_dump() for binding in created.bindings] == [
            GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=100, slug="platform").model_dump()
        ]
        assert created.description == "Imported from GitHub team acme/platform"

    @pytest.mark.asyncio
    async def test_creation_is_off_unless_the_instance_syncs_teams(self):
        """The bound team that holds nothing is what carries the resolution past the shortcut for
        an organisation with no binding at all, so the switch itself is what this proves."""
        service = _service()
        team_repo = _team_repo(_bound("t-pay", 4711))

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM) as stubs:
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult([])
        team_repo.create.assert_not_called()
        stubs.repo_map.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_team_with_no_resolvable_member_is_still_created(self):
        """GitHub logins are personal handles and usernames are directory ids, so barely one resolves.
        Requiring a member, as the GitLab sync does, would mean never creating anything here."""
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(
            service, team_repo, repo_map=_HELD_BY_PLATFORM, members=_ONE_MAINTAINER, user_repo=_user_repo()
        ):
            with patch.object(service, "get_user_public_email", new=AsyncMock(return_value=None)):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = self._created(team_repo)
        assert created.members == []
        assert result == GitHubTeamSyncResult([str(created.id)])

    @pytest.mark.asyncio
    async def test_every_group_holding_the_repository_becomes_an_owner(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map={"acme/widgets": [100, 900]}):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = [call.args[0] for call in team_repo.create.await_args_list]
        assert [team.name for team in created] == ["GitHub Team: acme/platform", "GitHub Team: acme/cards"]
        assert result == GitHubTeamSyncResult([str(team.id) for team in created])

    @pytest.mark.asyncio
    async def test_a_group_already_bound_to_a_team_is_adopted_rather_than_created_twice(self):
        """The second repository of the same group, or one whose binding names another organisation."""
        service = _service(sync_teams=True)
        team_repo = _team_repo(adopted=_bound("t-platform", 100, slug="platform", name="Platform"))

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-platform"])
        team_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_group_created_by_a_concurrent_ingest_is_adopted(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo()
        team_repo.get_raw_by_binding = AsyncMock(
            side_effect=[None, _bound("t-raced", 100, slug="platform", name="GitHub Team: acme/platform")]
        )
        team_repo.create = AsyncMock(side_effect=DuplicateKeyError("teams index"))

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-raced"])

    @pytest.mark.asyncio
    async def test_a_bound_team_that_answered_no_is_not_created_a_second_time_from_the_map(self):
        """The direct check is the fresher answer; the map may be up to its whole TTL behind it."""
        service = _service(sync_teams=True)
        team_repo = _team_repo(_bound("t-platform", 100, slug="platform", name="Platform"))

        with _sync_stubs(service, team_repo, access={"platform": False}, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult([])
        team_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_repository_no_group_holds_keeps_no_github_owner(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map={"acme/gadgets": [100]}):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult([])
        team_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_an_unfinished_walk_leaves_the_owners_untouched_rather_than_reporting_nobody(self, caplog):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map=None):
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None)
        team_repo.create.assert_not_called()
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_a_group_the_organisation_no_longer_lists_is_left_out(self, caplog):
        """The map outlives the team listing, so a group dissolved since the walk lands here."""
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map={"acme/widgets": [6666]}):
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult([])
        team_repo.create.assert_not_called()
        assert any("6666" in record.getMessage() for record in caplog.records if record.levelname == "WARNING")

    @pytest.mark.asyncio
    async def test_the_repository_is_found_whatever_case_github_spells_it_in(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "Acme/Widgets")

        assert result == GitHubTeamSyncResult([str(self._created(team_repo).id)])

    @pytest.mark.asyncio
    async def test_the_members_of_a_created_team_are_synced_like_any_other_holder(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM) as stubs:
            await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert stubs.members.await_args.args == ("acme", "platform", 100)
        assert team_repo.update_with_binding.await_args.args[1]["members"] == [
            {"user_id": "u-1", "role": "admin", "source": "github"}
        ]


def _unbound(doc_id: str, name: str) -> dict:
    return {"_id": doc_id, "name": name}


class TestAdoptionByName:
    """Four of the groups holding a scanned repository here are teams the owner already has under
    their own name; creating beside them lists every one of their projects twice."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("slug", "name"),
        [
            ("team-shangri-llama", "Shangri Llama"),
            ("team-orion", "Orion"),
            ("team_atlas", "Atlas"),
            ("platform", "Platform"),
        ],
    )
    async def test_an_existing_team_of_the_same_name_is_bound_rather_than_duplicated(self, slug, name):
        service = _service("gh-1", sync_teams=True)
        team_repo = _team_repo(unbound=[_unbound("t-existing", name)])
        org_teams = [{"id": 100, "slug": slug, "name": name, "parent": None}]

        with _sync_stubs(service, team_repo, org_teams=org_teams, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-existing"])
        team_repo.create.assert_not_called()
        assert team_repo.add_binding_if_absent.await_args.args == (
            "t-existing",
            GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=100, slug=slug).model_dump(),
        )

    @pytest.mark.asyncio
    async def test_the_adopted_team_keeps_the_name_it_already_had(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo(unbound=[_unbound("t-existing", "Shangri Llama")])
        org_teams = [{"id": 100, "slug": "team-shangri-llama", "parent": None}]

        with _sync_stubs(service, team_repo, org_teams=org_teams, repo_map=_HELD_BY_PLATFORM):
            await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert "name" not in team_repo.update_with_binding.await_args.args[1]

    @pytest.mark.asyncio
    async def test_a_name_that_only_nearly_matches_gets_its_own_team(self):
        """"team-qala" and "QAlas" are one letter apart and two different teams; guessing which
        near-misses are the same team is how a sync hands a project to strangers."""
        service = _service(sync_teams=True)
        team_repo = _team_repo(unbound=[_unbound("t-qalas", "QAlas")])
        org_teams = [{"id": 100, "slug": "team-qala", "parent": None}]

        with _sync_stubs(service, team_repo, org_teams=org_teams, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = team_repo.create.await_args.args[0]
        assert created.name == "GitHub Team: acme/team-qala"
        assert result == GitHubTeamSyncResult([str(created.id)])
        team_repo.add_binding_if_absent.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_name_two_teams_answer_to_is_adopted_by_neither(self, caplog):
        service = _service(sync_teams=True)
        team_repo = _team_repo(unbound=[_unbound("t-a", "Orion"), _unbound("t-b", "orion!")])
        org_teams = [{"id": 100, "slug": "team-orion", "parent": None}]

        with _sync_stubs(service, team_repo, org_teams=org_teams, repo_map=_HELD_BY_PLATFORM):
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = team_repo.create.await_args.args[0]
        assert result == GitHubTeamSyncResult([str(created.id)])
        team_repo.add_binding_if_absent.assert_not_awaited()
        warnings = " ".join(record.getMessage() for record in caplog.records if record.levelname == "WARNING")
        assert "Orion" in warnings and "orion!" in warnings

    @pytest.mark.asyncio
    async def test_a_team_another_ingest_bound_first_is_not_adopted(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo(unbound=[_unbound("t-existing", "Platform")])
        team_repo.add_binding_if_absent = AsyncMock(return_value=None)

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        created = team_repo.create.await_args.args[0]
        assert result == GitHubTeamSyncResult([str(created.id)])

    @pytest.mark.asyncio
    async def test_a_group_already_bound_is_never_looked_up_by_name(self):
        """The binding is the answer; a same-named team must not be pulled in beside it."""
        service = _service(sync_teams=True)
        team_repo = _team_repo(adopted=_bound("t-platform", 100, slug="platform", name="Platform"))

        with _sync_stubs(service, team_repo, repo_map=_HELD_BY_PLATFORM):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(["t-platform"])
        team_repo.find_raw_unbound_for_instance.assert_not_awaited()


_SIX_GROUPS = (100, 900, 4711, 500, 101, 902)
_SIX_HOLDERS = {"acme/widgets": list(_SIX_GROUPS)}
_SIX_TEAMS = [{"id": team_id, "slug": f"g{team_id}", "parent": None} for team_id in _SIX_GROUPS]


class TestOwnerBudget:
    """A team created for an ownership write that is then refused owns nothing at all."""

    @pytest.mark.asyncio
    async def test_more_holders_than_the_project_has_room_for_creates_nothing(self, caplog):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, org_teams=_SIX_TEAMS, repo_map=_SIX_HOLDERS):
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = await service.sync_team_from_github(
                    MagicMock(), "acme", "acme/widgets", owner_budget=5
                )

        assert result == GitHubTeamSyncResult(None)
        team_repo.create.assert_not_called()
        warnings = " ".join(record.getMessage() for record in caplog.records if record.levelname == "WARNING")
        assert "g100" in warnings and "room for 5" in warnings

    @pytest.mark.asyncio
    async def test_holders_that_fit_are_created_and_owned(self):
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, org_teams=_SIX_TEAMS, repo_map=_SIX_HOLDERS):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets", owner_budget=6)

        assert team_repo.create.await_count == 6
        assert result.team_ids is not None and len(result.team_ids) == 6

    @pytest.mark.asyncio
    async def test_a_resolution_the_budget_refuses_writes_no_owner_either(self):
        """The two go together: the refusal is what keeps the created team from being an orphan."""
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        with _sync_stubs(service, team_repo, org_teams=_SIX_TEAMS, repo_map=_SIX_HOLDERS):
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets", owner_budget=0)

        assert result.team_ids is None
        team_repo.create.assert_not_called()
        team_repo.update_with_binding.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_resolution_abandoned_on_the_timeout_creates_nothing(self):
        """The budget bounds the reads; a half-written set of teams would outlive the ingest."""
        service = _service(sync_teams=True)
        team_repo = _team_repo()

        async def _never_answers(*_args, **_kwargs):
            await asyncio.sleep(60)
            raise AssertionError("the resolution step should have been abandoned")

        with _sync_stubs(service, team_repo, org_teams=_SIX_TEAMS, repo_map=_SIX_HOLDERS) as stubs:
            stubs.repo_map.side_effect = _never_answers
            with patch("app.services.github._GITHUB_RESOLUTION_TIMEOUT", 0.05):
                result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")

        assert result == GitHubTeamSyncResult(None)
        team_repo.create.assert_not_called()


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
            return False

        with _sync_stubs(service, _team_repo(*bound), org_teams=org_teams) as stubs:
            stubs.checks.side_effect = _slow_check
            started = time.perf_counter()
            result = await service.sync_team_from_github(MagicMock(), "acme", "acme/widgets")
            elapsed = time.perf_counter() - started

        assert result == GitHubTeamSyncResult([])
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

        assert result == GitHubTeamSyncResult(None)
        assert elapsed < 1
        assert any("acme/widgets" in record.getMessage() for record in caplog.records)
