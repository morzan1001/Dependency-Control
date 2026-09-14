"""An empty GitLab group and an unreachable one demand opposite writes.

A group nobody is left in must have its members removed; a group GitLab could not answer for must
be left exactly as it is. Anything that turns a failure into a falsy value collapses the two.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import TEAM_SOURCE_GITLAB, team_source
from app.models.gitlab_api import GitLabMember
from app.services.gitlab import GitLabGroupLookup, GitLabService
from tests.mocks.gitlab import make_gitlab_instance, make_project_details
from tests.mocks.mongodb import create_mock_collection, create_mock_db

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
        "bindings": [{"provider": "gitlab", "instance_id": "instance-a-id", "external_id": 42}],
    }


def _run(service, db):
    return asyncio.run(
        service.sync_team_from_gitlab(
            db=db,
            gitlab_project_id=100,
            gitlab_project_path="grp/proj",
            gitlab_project_data=make_project_details(namespace_kind="group", namespace_id=42, namespace_path="grp"),
        )
    )


def _db(existing_team, user_doc=None):
    teams = create_mock_collection(find_one=existing_team)
    users = create_mock_collection(find_one=user_doc)
    return create_mock_db({"teams": teams, "users": users}), teams


def _written_members(teams_coll):
    return teams_coll.update_one.call_args[0][1]["$set"].get("members")


class TestAnEmptyGroupRetiresItsMembers:
    def test_a_group_nobody_is_left_in_empties_the_gitlab_subset(self):
        service = _service()
        db, teams = _db(_existing_team([_SYNCED, _MANUAL]))

        with patch.object(service, "get_group_members", new=AsyncMock(return_value=[])):
            result = _run(service, db)

        assert result.team_ids == ["existing-team-id"]
        assert _written_members(teams) == [_MANUAL]

    def test_an_empty_group_spares_the_members_another_instance_established(self):
        service = _service()
        db, teams = _db(_existing_team([_SYNCED, _OTHER_INSTANCE]))

        with patch.object(service, "get_group_members", new=AsyncMock(return_value=[])):
            _run(service, db)

        assert _written_members(teams) == [_OTHER_INSTANCE]


class TestAnUnreachableGroupChangesNothing:
    def test_a_failed_member_fetch_leaves_the_stored_members_untouched(self):
        service = _service()
        db, teams = _db(_existing_team([_SYNCED, _MANUAL]))

        with patch.object(service, "get_group_members", new=AsyncMock(return_value=None)):
            result = _run(service, db)

        assert result.team_ids == ["existing-team-id"]
        teams.update_one.assert_not_called()

    def test_a_failed_member_fetch_never_creates_a_team(self):
        service = _service()
        teams = create_mock_collection(find_one=None)
        teams.insert_one = AsyncMock()
        db = create_mock_db({"teams": teams, "users": create_mock_collection()})

        with patch.object(service, "get_group_members", new=AsyncMock(return_value=None)):
            result = _run(service, db)

        assert result.team_ids is None
        teams.insert_one.assert_not_called()

    def test_an_unanswered_group_lookup_leaves_the_owner_undetermined(self):
        """A transient failure must not quietly re-bind the project to a deeper group."""
        service = _service()
        teams = create_mock_collection(find_one=None)
        teams.insert_one = AsyncMock()
        db = create_mock_db({"teams": teams, "users": create_mock_collection()})

        with (
            patch.object(service, "get_group_members", new=AsyncMock()) as members,
            patch.object(
                service,
                "_resolve_group_by_path",
                new=AsyncMock(return_value=GitLabGroupLookup(reachable=False, group=None)),
            ),
        ):
            result = asyncio.run(
                service.sync_team_from_gitlab(
                    db=db,
                    gitlab_project_id=100,
                    gitlab_project_path="org/subgroup/proj",
                    gitlab_project_data=make_project_details(
                        namespace_kind="group", namespace_id=42, namespace_path="org/subgroup"
                    ),
                )
            )

        assert result.team_ids is None
        members.assert_not_awaited()
        teams.insert_one.assert_not_called()

    def test_members_that_all_fail_to_resolve_leave_the_stored_members_untouched(self, caplog):
        """A token that lost profile access resolves nobody, which is not a group everyone left."""
        service = _service()
        db, teams = _db(_existing_team([_SYNCED, _MANUAL]), user_doc=None)
        members = [
            GitLabMember(username="ada", email="ada@test.com", access_level=40),
            GitLabMember(username="bob", email="bob@test.com", access_level=30),
        ]

        with patch.object(service, "get_group_members", new=AsyncMock(return_value=members)):
            with caplog.at_level("WARNING", logger="app.services.gitlab"):
                result = _run(service, db)

        assert result.team_ids == ["existing-team-id"]
        assert _written_members(teams) is None
        assert "0 of 2" in " ".join(r.getMessage() for r in caplog.records)


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
        db, _ = _db(None)

        with patch.object(service, "get_group_members", new=AsyncMock(side_effect=RuntimeError("boom"))):
            assert _run(service, db).team_ids is None
