"""An empty GitLab group and an unreachable one demand opposite writes.

A group nobody is left in must have its members removed; a group GitLab could not answer for must
be left exactly as it is. Anything that turns a failure into a falsy value collapses the two.
"""

import asyncio
from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import TEAM_SOURCE_GITLAB, team_source
from app.models.gitlab_api import GitLabMember
from app.repositories.teams import MemberSubset
from app.services.gitlab import GitLabGroupLookup, GitLabService
from tests.mocks.gitlab import make_gitlab_instance, make_project_details, make_repositories

_OWN = team_source(TEAM_SOURCE_GITLAB, "instance-a-id")
_MANUAL = {"user_id": "u-manual", "role": "member", "source": "manual"}
_OTHER_INSTANCE = {"user_id": "u-elsewhere", "role": "member", "source": team_source(TEAM_SOURCE_GITLAB, "instance-b")}
_SYNCED = {"user_id": "u-1", "role": "admin", "source": _OWN}


def _service():
    return GitLabService(make_gitlab_instance(id="instance-a-id", name="GitLab A", url="https://gitlab-a.com"))


def _existing_team(members):
    return {
        "_id": "existing-team-id",
        "name": "GitLab Group: grp",
        "members": members,
        "bindings": [{"provider": "gitlab", "instance_id": "instance-a-id", "external_id": 42, "path": "grp"}],
    }


def _run(service):
    return asyncio.run(
        service.sync_team_from_gitlab(
            db=MagicMock(),
            gitlab_project_id=100,
            gitlab_project_path="grp/proj",
            gitlab_project_data=make_project_details(namespace_kind="group", namespace_id=42, namespace_path="grp"),
        )
    )


def _written_subset(team_repo) -> MemberSubset | None:
    """The members the write hands the server, which merges them into the stored array itself."""
    return team_repo.update_with_binding.await_args.args[4]


class TestAnEmptyGroupRetiresItsMembers:
    def test_a_group_nobody_is_left_in_empties_the_gitlab_subset(self):
        service = _service()

        with (
            make_repositories(existing_team=_existing_team([_SYNCED, _MANUAL])) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=[])),
        ):
            result = _run(service)

        assert result.team_ids == ["existing-team-id"]
        assert _written_subset(team_repo) == MemberSubset(_OWN, [])

    def test_an_empty_group_spares_the_members_another_instance_established(self):
        service = _service()

        with (
            make_repositories(existing_team=_existing_team([_SYNCED, _OTHER_INSTANCE])) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=[])),
        ):
            _run(service)

        # The subset names this instance, and the server replaces no entry outside it.
        assert _written_subset(team_repo).source == _OWN


class TestAnUnreachableGroupChangesNothing:
    def test_a_failed_member_fetch_leaves_the_stored_members_untouched(self):
        service = _service()

        with (
            make_repositories(existing_team=_existing_team([_SYNCED, _MANUAL])) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=None)),
        ):
            result = _run(service)

        assert result.team_ids == ["existing-team-id"]
        team_repo.update_with_binding.assert_not_called()

    def test_a_failed_member_fetch_never_creates_a_team(self):
        service = _service()

        with (
            make_repositories() as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=None)),
        ):
            result = _run(service)

        assert result.team_ids is None
        team_repo.create.assert_not_called()

    def test_an_unanswered_group_lookup_leaves_the_owner_undetermined(self):
        """A transient failure must not quietly re-bind the project to a deeper group."""
        service = _service()

        with (
            make_repositories() as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock()) as members,
            patch.object(
                service,
                "_resolve_group_by_path",
                new=AsyncMock(return_value=GitLabGroupLookup(reachable=False, group=None)),
            ),
        ):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=100,
                    gitlab_project_path="org/subgroup/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group", namespace_id=42, namespace_path="org/subgroup"
                    ),
                )
            )

        assert result.team_ids is None
        members.assert_not_awaited()
        team_repo.create.assert_not_called()

    def test_a_parent_path_the_token_cannot_see_leaves_the_owner_undetermined(self):
        """A 404 on an ancestor is a group the token may not see; binding the deepest namespace
        instead would split the group's people across two teams of different granularity."""
        service = _service()

        with (
            make_repositories() as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock()) as members,
            patch.object(
                service,
                "_resolve_group_by_path",
                new=AsyncMock(return_value=GitLabGroupLookup(reachable=True, group=None)),
            ),
        ):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=100,
                    gitlab_project_path="org/subgroup/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group", namespace_id=42, namespace_path="org/subgroup"
                    ),
                )
            )

        assert result.team_ids is None
        members.assert_not_awaited()
        team_repo.create.assert_not_called()

    def test_members_that_all_fail_to_resolve_leave_the_stored_members_untouched(self, caplog):
        """A token that lost profile access resolves nobody, which is not a group everyone left."""
        service = _service()
        members = [
            GitLabMember(username="ada", email="ada@test.com", access_level=40),
            GitLabMember(username="bob", email="bob@test.com", access_level=30),
        ]

        with (
            make_repositories(existing_team=_existing_team([_SYNCED, _MANUAL])) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=members)),
            caplog.at_level("WARNING", logger="app.services.gitlab"),
        ):
            result = _run(service)

        assert result.team_ids == ["existing-team-id"]
        team_repo.update_with_binding.assert_not_called()
        assert "0 of 2" in " ".join(r.getMessage() for r in caplog.records)


class TestNoGroupOwnsTheProject:
    def test_a_user_namespace_retires_the_group_owner_the_project_carried(self):
        """GitLab answered, and its answer is that a person owns this project: determined, not unknown."""
        service = _service()

        with make_repositories() as (team_repo, _):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=MagicMock(),
                    gitlab_project_id=100,
                    gitlab_project_path="john/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="user", namespace_id=1, namespace_path="john"
                    ),
                )
            )

        assert result.team_ids == []
        team_repo.create.assert_not_called()
        team_repo.update_with_binding.assert_not_called()


class TestATeamNothingChangedAboutIsNotWritten:
    """Every CI job of every pipeline syncs, so a bare updated_at bump is a write per job over a
    team nothing changed about."""

    # Nobody resolves, so the members are left alone and only a rename or a move is left to write.
    _UNRESOLVABLE: ClassVar = [GitLabMember(username="ghost", email="ghost@test.com", access_level=30)]

    def test_a_team_nothing_changed_about_is_not_written_at_all(self):
        service = _service()

        with (
            make_repositories(existing_team=_existing_team([_MANUAL])) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=self._UNRESOLVABLE)),
        ):
            _run(service)

        team_repo.update_with_binding.assert_not_called()

    def test_a_moved_group_still_restamps_the_path_it_resolved_through(self):
        service = _service()
        stored = _existing_team([_MANUAL])
        stored["bindings"][0]["path"] = "old"

        with (
            make_repositories(existing_team=stored) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=self._UNRESOLVABLE)),
        ):
            _run(service)

        assert team_repo.update_with_binding.await_args.args[3] == {"path": "grp"}

    def test_a_team_still_carrying_the_generated_name_follows_a_renamed_group(self):
        service = _service()
        stored = _existing_team([_MANUAL])
        stored["name"] = "GitLab Group: old"

        with (
            make_repositories(existing_team=stored) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=self._UNRESOLVABLE)),
        ):
            _run(service)

        assert team_repo.update_with_binding.await_args.args[1]["name"] == "GitLab Group: grp"

    def test_a_team_its_owner_renamed_keeps_that_name(self):
        service = _service()
        stored = _existing_team([_MANUAL])
        stored["name"] = "BOS"

        with (
            make_repositories(existing_team=stored) as (team_repo, _),
            patch.object(service, "get_group_members", new=AsyncMock(return_value=self._UNRESOLVABLE)),
        ):
            _run(service)

        team_repo.update_with_binding.assert_not_called()


class TestTheMemberFetchKeepsEmptyAndFailureApart:
    @pytest.mark.parametrize(
        ("paginated", "expected"),
        [([], []), (None, None)],
        ids=["an empty group stays an empty list", "a failed fetch stays None"],
    )
    def test_group_members(self, paginated, expected):
        service = _service()

        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=paginated)):
            assert asyncio.run(service.get_group_members(42)) == expected

    @pytest.mark.parametrize(
        ("paginated", "expected"),
        [([], []), (None, None)],
        ids=["an empty project stays an empty list", "a failed fetch stays None"],
    )
    def test_project_members(self, paginated, expected):
        service = _service()

        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=paginated)):
            assert asyncio.run(service.get_project_members(42)) == expected


class TestTheGroupLookupKeepsAbsentAndUnreachableApart:
    @staticmethod
    def _lookup(response):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)):
            return asyncio.run(service._resolve_group_by_path("org/edge"))

    def test_a_group_the_instance_carries_is_returned(self):
        response = MagicMock(status_code=200)
        response.json.return_value = {"id": 10, "full_path": "org/edge"}

        assert self._lookup(response) == GitLabGroupLookup(reachable=True, group={"id": 10, "full_path": "org/edge"})

    def test_a_path_the_instance_does_not_carry_is_reachable_and_absent(self):
        assert self._lookup(MagicMock(status_code=404)) == GitLabGroupLookup(reachable=True, group=None)

    def test_an_unanswered_request_is_not_an_absent_group(self):
        assert self._lookup(None) == GitLabGroupLookup(reachable=False, group=None)

    def test_a_refused_request_is_not_an_absent_group(self):
        assert self._lookup(MagicMock(status_code=403)) == GitLabGroupLookup(reachable=False, group=None)


class TestTheSyncNeverRaises:
    def test_an_exception_reports_nothing_determined(self):
        service = _service()

        with (
            make_repositories(),
            patch.object(service, "get_group_members", new=AsyncMock(side_effect=RuntimeError("boom"))),
        ):
            assert _run(service).team_ids is None

    def test_reads_that_outlast_the_budget_leave_the_owner_undetermined(self, caplog):
        """The reads run inside the ingest request, and the member listing is uncapped."""
        service = _service()

        async def _never_answers(_group_id):
            await asyncio.sleep(3600)

        with (
            make_repositories(existing_team=_existing_team([_MANUAL])) as (team_repo, _),
            patch("app.services.gitlab._GITLAB_RESOLUTION_TIMEOUT", 0.01),
            patch.object(service, "get_group_members", new=_never_answers),
            caplog.at_level("WARNING", logger="app.services.gitlab"),
        ):
            result = _run(service)

        assert result.team_ids is None
        team_repo.update_with_binding.assert_not_called()
        assert "longer than" in " ".join(r.getMessage() for r in caplog.records)
