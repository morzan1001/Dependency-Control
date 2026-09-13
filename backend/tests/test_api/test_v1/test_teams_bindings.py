"""Binding a team to a group on one instance: the only writer of what resolution reads."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError

from app.api.deps import PermissionChecker
from app.core.permissions import Permissions
from app.schemas.team import TeamGitHubBindingRequest, TeamGitLabBindingRequest
from app.services.gitlab import GitLabGroupLookup
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance

MODULE = "app.api.v1.endpoints.teams"
_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)

_ORG_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "parent": None},
    {"id": 900, "slug": "cards", "name": "Cards", "parent": {"id": 4711, "slug": "payments"}},
]
_GROUP = {"id": 77, "path": "edge", "full_path": "mo/edge", "name": "Edge"}
_FOUND = GitLabGroupLookup(reachable=True, group=_GROUP)
_ABSENT = GitLabGroupLookup(reachable=True, group=None)
_UNREACHABLE = GitLabGroupLookup(reachable=False, group=None)

_GITHUB = TeamGitHubBindingRequest(provider="github", instance_id="gh-1", org="Acme", external_id=4711)
_GITLAB = TeamGitLabBindingRequest(provider="gitlab", instance_id="gl-1", external_id=77)


def _github_binding(instance_id="gh-1", external_id=4711, org="acme", slug="payments") -> dict:
    return {
        "provider": "github",
        "instance_id": instance_id,
        "external_id": external_id,
        "org": org,
        "slug": slug,
        "key": f"github:{instance_id}:{external_id}",
    }


def _gitlab_binding(instance_id="gl-1", external_id=77, path="mo/edge") -> dict:
    return {
        "provider": "gitlab",
        "instance_id": instance_id,
        "external_id": external_id,
        "path": path,
        "key": f"gitlab:{instance_id}:{external_id}",
    }


def _db(*teams) -> FakeDatabase:
    db = FakeDatabase()
    for team in teams:
        db.teams._docs[team["_id"]] = team
    return db


def _team(team_id: str = "team-1", name: str = "Payments Guild", *bindings) -> dict:
    return {
        "_id": team_id,
        "name": name,
        "members": [],
        "bindings": list(bindings),
        "created_at": _TIMESTAMP,
        "updated_at": _TIMESTAMP,
    }


def _run_bind(db, binding=_GITHUB, *, org_teams=_ORG_TEAMS, lookup=_FOUND, team_id="team-1"):
    from app.api.v1.endpoints.teams import set_team_binding

    github_instances = MagicMock()
    github_instances.get_by_id = AsyncMock(return_value=make_github_instance(id="gh-1", access_token="ghp-secret"))
    github = MagicMock()
    github.get_org_teams = AsyncMock(return_value=org_teams)
    gitlab_instances = MagicMock()
    gitlab_instances.get_by_id = AsyncMock(return_value=make_gitlab_instance(id="gl-1"))
    gitlab = MagicMock()
    gitlab.get_group = AsyncMock(return_value=lookup)

    with (
        patch(f"{MODULE}.GitHubInstanceRepository", return_value=github_instances),
        patch(f"{MODULE}.GitHubService", return_value=github),
        patch(f"{MODULE}.GitLabInstanceRepository", return_value=gitlab_instances),
        patch(f"{MODULE}.GitLabService", return_value=gitlab),
    ):
        return asyncio.run(
            set_team_binding(
                team_id=team_id,
                binding_in=binding,
                current_user=MagicMock(username="admin"),
                db=db,
            )
        )


def _stored(db, team_id="team-1") -> dict:
    return db.teams._docs[team_id]


def _bindings(db, team_id="team-1") -> list[dict]:
    return _stored(db, team_id)["bindings"]


class TestSetBinding:
    def test_a_github_binding_carries_everything_resolution_reads(self):
        db = _db(_team())

        response = _run_bind(db)

        assert _bindings(db) == [_github_binding(org="Acme")]
        assert [binding.key for binding in response.bindings] == ["github:gh-1:4711"]

    def test_a_gitlab_binding_carries_everything_resolution_reads(self):
        db = _db(_team())

        response = _run_bind(db, _GITLAB)

        assert _bindings(db) == [_gitlab_binding()]
        assert [binding.key for binding in response.bindings] == ["gitlab:gl-1:77"]

    def test_the_slug_comes_from_the_organisation_listing_not_from_the_caller(self):
        """A slug the caller invented would address whichever team took that name."""
        db = _db(_team())

        _run_bind(db, TeamGitHubBindingRequest(provider="github", instance_id="gh-1", org="Acme", external_id=900))

        assert _bindings(db)[0]["slug"] == "cards"

    def test_the_path_comes_from_the_instance_not_from_the_caller(self):
        db = _db(_team())

        _run_bind(db, _GITLAB)

        assert _bindings(db)[0]["path"] == "mo/edge"

    def test_a_team_the_organisation_does_not_list_is_refused(self):
        """Binding a number no organisation carries stores a binding that resolves nothing, silently."""
        db = _db(_team())
        unknown = TeamGitHubBindingRequest(provider="github", instance_id="gh-1", org="Acme", external_id=6666)

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, unknown)

        assert excinfo.value.status_code == 400
        assert _bindings(db) == []

    def test_a_group_the_instance_does_not_carry_is_refused(self):
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, _GITLAB, lookup=_ABSENT)

        assert excinfo.value.status_code == 400
        assert _bindings(db) == []

    def test_an_unreadable_organisation_is_a_bad_gateway_rather_than_a_guess(self):
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, org_teams=None)

        assert excinfo.value.status_code == 502
        assert _bindings(db) == []

    def test_an_unreachable_instance_is_a_bad_gateway_rather_than_a_guess(self):
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, _GITLAB, lookup=_UNREACHABLE)

        assert excinfo.value.status_code == 502
        assert _bindings(db) == []

    def test_an_unknown_team_is_not_found(self):
        with pytest.raises(HTTPException) as excinfo:
            _run_bind(_db(_team()), team_id="team-absent")

        assert excinfo.value.status_code == 404

    @pytest.mark.parametrize(
        ("request_in", "repository"),
        [(_GITHUB, "GitHubInstanceRepository"), (_GITLAB, "GitLabInstanceRepository")],
    )
    def test_an_unknown_instance_is_not_found(self, request_in, repository):
        from app.api.v1.endpoints.teams import set_team_binding

        db = _db(_team())
        instances = MagicMock()
        instances.get_by_id = AsyncMock(return_value=None)

        with patch(f"{MODULE}.{repository}", return_value=instances):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(
                    set_team_binding(
                        team_id="team-1",
                        binding_in=request_in,
                        current_user=MagicMock(username="admin"),
                        db=db,
                    )
                )

        assert excinfo.value.status_code == 404
        assert _bindings(db) == []


class TestOneBindingPerInstance:
    def test_a_team_holds_a_binding_on_each_of_two_instances_of_one_provider(self):
        db = _db(_team("team-1", "Payments Guild", _github_binding(instance_id="gh-2", external_id=12)))

        _run_bind(db)

        assert sorted(binding["key"] for binding in _bindings(db)) == ["github:gh-1:4711", "github:gh-2:12"]

    def test_a_team_holds_a_binding_on_each_provider(self):
        db = _db(_team("team-1", "Payments Guild", _github_binding()))

        _run_bind(db, _GITLAB)

        assert sorted(binding["key"] for binding in _bindings(db)) == ["github:gh-1:4711", "gitlab:gl-1:77"]

    def test_rebinding_the_same_instance_replaces_the_entry_rather_than_adding_one(self):
        """Two entries for one instance would have that instance's sync resolve two groups onto
        one member list, and the multikey index cannot refuse a duplicate inside one document."""
        db = _db(_team("team-1", "Payments Guild", _github_binding(external_id=900, slug="cards")))

        _run_bind(db)

        assert _bindings(db) == [_github_binding(org="Acme")]

    def test_rebinding_a_team_to_the_binding_it_already_holds_refreshes_the_slug(self):
        db = _db(_team("team-1", "Payments Guild", _github_binding(slug="pay-old")))

        _run_bind(db)

        assert _bindings(db) == [_github_binding(org="Acme")]


class TestBindingUniqueness:
    def test_a_github_team_another_team_already_holds_is_refused(self):
        """Two teams bound to one GitHub team would make the repository's owner ambiguous."""
        db = _db(_team(), _team("team-2", "Payments", _github_binding()))

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db)

        assert excinfo.value.status_code == 409
        assert "Payments" in excinfo.value.detail
        assert _bindings(db) == []

    def test_a_gitlab_group_another_team_already_holds_is_refused(self):
        db = _db(_team(), _team("team-2", "Platform", _gitlab_binding()))

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, _GITLAB)

        assert excinfo.value.status_code == 409
        assert "Platform" in excinfo.value.detail
        assert _bindings(db) == []

    def test_the_same_team_number_on_another_instance_is_a_different_binding(self):
        db = _db(_team(), _team("team-2", "Billing", _github_binding(instance_id="gh-2")))

        _run_bind(db)

        assert _bindings(db) == [_github_binding(org="Acme")]

    def test_the_same_group_number_on_another_instance_is_a_different_binding(self):
        db = _db(_team(), _team("team-2", "Billing", _gitlab_binding(instance_id="gl-2")))

        _run_bind(db, _GITLAB)

        assert _bindings(db) == [_gitlab_binding()]

    def test_a_binding_taken_between_the_check_and_the_write_is_a_conflict_not_a_crash(self):
        """The unique index is the only thing that can see a concurrent write; a 500 would tell
        the operator the binding failed for an unknown reason."""
        from app.api.v1.endpoints.teams import set_team_binding

        team_repo = MagicMock()
        team_repo.get_raw_by_id = AsyncMock(return_value=_team())
        team_repo.get_raw_by_binding_key = AsyncMock(return_value=None)
        team_repo.replace_binding_for_instance = AsyncMock(side_effect=DuplicateKeyError("E11000 duplicate key"))
        instance_repo = MagicMock()
        instance_repo.get_by_id = AsyncMock(return_value=make_github_instance(id="gh-1", access_token="ghp-secret"))
        service = MagicMock()
        service.get_org_teams = AsyncMock(return_value=_ORG_TEAMS)

        with (
            patch(f"{MODULE}.TeamRepository", return_value=team_repo),
            patch(f"{MODULE}.GitHubInstanceRepository", return_value=instance_repo),
            patch(f"{MODULE}.GitHubService", return_value=service),
        ):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(
                    set_team_binding(
                        team_id="team-1",
                        binding_in=_GITHUB,
                        current_user=MagicMock(username="admin"),
                        db=MagicMock(),
                    )
                )

        assert excinfo.value.status_code == 409


class TestClearBinding:
    def _run(self, db, instance_id="gh-1", team_id="team-1"):
        from app.api.v1.endpoints.teams import clear_team_binding

        return asyncio.run(
            clear_team_binding(
                team_id=team_id, instance_id=instance_id, current_user=MagicMock(username="admin"), db=db
            )
        )

    def test_the_named_instance_loses_its_binding_and_the_others_keep_theirs(self):
        """A mis-binding has to be reversible without disturbing the instances it says nothing about."""
        db = _db(
            _team(
                "team-1",
                "Payments Guild",
                _github_binding(),
                _github_binding(instance_id="gh-2", external_id=12),
                _gitlab_binding(),
            )
        )

        response = self._run(db)

        assert sorted(binding["key"] for binding in _bindings(db)) == ["github:gh-2:12", "gitlab:gl-1:77"]
        assert sorted(binding.key for binding in response.bindings) == ["github:gh-2:12", "gitlab:gl-1:77"]

    def test_an_instance_the_team_is_not_bound_to_is_not_found(self):
        db = _db(_team("team-1", "Payments Guild", _github_binding()))

        with pytest.raises(HTTPException) as excinfo:
            self._run(db, instance_id="gh-9")

        assert excinfo.value.status_code == 404
        assert len(_bindings(db)) == 1

    def test_an_unknown_team_is_not_found(self):
        with pytest.raises(HTTPException) as excinfo:
            self._run(_db(_team()), team_id="team-absent")

        assert excinfo.value.status_code == 404


class TestBindingIsGatedOnSystemManage:
    """A binding decides which projects of the estate land in the team, and team membership
    grants access to them, so team administration alone must not be enough."""

    @staticmethod
    def _required_permissions(path: str, method: str) -> list[list[str]]:
        from app.api.v1.endpoints.teams import router

        route = next(route for route in router.routes if route.path == path and method in route.methods)
        return [
            dependency.call.required_permissions
            for dependency in route.dependant.dependencies
            if isinstance(dependency.call, PermissionChecker)
        ]

    @pytest.mark.parametrize(
        ("path", "method"),
        [("/{team_id}/bindings", "PUT"), ("/{team_id}/bindings/{instance_id}", "DELETE")],
    )
    def test_both_binding_routes_demand_system_manage(self, path, method):
        assert self._required_permissions(path, method) == [[Permissions.SYSTEM_MANAGE]]
