"""Binding a team to a GitLab group by hand: the manual writer of the fields resolution reads."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError

from app.api.deps import PermissionChecker
from app.core.permissions import Permissions
from app.schemas.team import TeamGitLabBindingUpdate
from app.services.gitlab import GitLabGroupLookup
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.gitlab import make_gitlab_instance

MODULE = "app.api.v1.endpoints.teams"
_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)

_GROUP = {"id": 77, "path": "edge", "full_path": "mo/edge", "name": "Edge"}
_FOUND = GitLabGroupLookup(reachable=True, group=_GROUP)
_ABSENT = GitLabGroupLookup(reachable=True, group=None)
_UNREACHABLE = GitLabGroupLookup(reachable=False, group=None)

_BINDING = TeamGitLabBindingUpdate(gitlab_instance_id="gl-1", gitlab_group_id=77)


def _db(*teams) -> FakeDatabase:
    db = FakeDatabase()
    for team in teams:
        db.teams._docs[team["_id"]] = team
    return db


def _team(team_id: str = "team-1", name: str = "Edge Guild", **binding) -> dict:
    return {
        "_id": team_id,
        "name": name,
        "members": [],
        "created_at": _TIMESTAMP,
        "updated_at": _TIMESTAMP,
        **binding,
    }


def _run_bind(db, binding=_BINDING, *, lookup=_FOUND, team_id="team-1", user=None):
    from app.api.v1.endpoints.teams import set_team_gitlab_binding

    instance_repo = MagicMock()
    instance_repo.get_by_id = AsyncMock(return_value=make_gitlab_instance(id="gl-1"))
    service = MagicMock()
    service.get_group = AsyncMock(return_value=lookup)

    with (
        patch(f"{MODULE}.GitLabInstanceRepository", return_value=instance_repo),
        patch(f"{MODULE}.GitLabService", return_value=service),
    ):
        return asyncio.run(
            set_team_gitlab_binding(
                team_id=team_id,
                binding_in=binding,
                current_user=user or MagicMock(username="admin"),
                db=db,
            )
        )


def _stored(db, team_id="team-1") -> dict:
    return db.teams._docs[team_id]


class TestSetBinding:
    def test_the_fields_resolution_reads_are_written(self):
        db = _db(_team())

        response = _run_bind(db)

        assert _stored(db)["gitlab_instance_id"] == "gl-1"
        assert _stored(db)["gitlab_group_id"] == 77
        assert response.gitlab_group_id == 77

    def test_the_path_comes_from_the_instance_not_from_the_caller(self):
        """A path the caller invented would label the binding as whichever group took that path."""
        db = _db(_team())

        _run_bind(db)

        assert _stored(db)["gitlab_group_path"] == "mo/edge"

    def test_a_group_the_instance_does_not_carry_is_refused(self):
        """Binding a number no instance carries stores a binding that resolves nothing, silently."""
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, lookup=_ABSENT)

        assert excinfo.value.status_code == 400
        assert "gitlab_group_id" not in _stored(db)

    def test_an_unreachable_instance_is_a_bad_gateway_rather_than_a_guess(self):
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, lookup=_UNREACHABLE)

        assert excinfo.value.status_code == 502
        assert "gitlab_group_id" not in _stored(db)

    def test_an_unknown_team_is_not_found(self):
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, team_id="team-absent")

        assert excinfo.value.status_code == 404

    def test_an_unknown_instance_is_not_found(self):
        from app.api.v1.endpoints.teams import set_team_gitlab_binding

        db = _db(_team())
        instance_repo = MagicMock()
        instance_repo.get_by_id = AsyncMock(return_value=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=instance_repo):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(
                    set_team_gitlab_binding(
                        team_id="team-1",
                        binding_in=_BINDING,
                        current_user=MagicMock(username="admin"),
                        db=db,
                    )
                )

        assert excinfo.value.status_code == 404
        assert "gitlab_group_id" not in _stored(db)

    def test_a_github_binding_the_team_holds_survives_a_gitlab_binding(self):
        """A team answers for one group of each provider; binding one must not clear the other."""
        db = _db(_team(github_instance_id="gh-1", github_org="Acme", github_team_id=4711))

        _run_bind(db)

        assert _stored(db)["github_team_id"] == 4711
        assert _stored(db)["gitlab_group_id"] == 77


class TestBindingUniqueness:
    def test_a_gitlab_group_another_team_already_holds_is_refused(self):
        """Two teams bound to one GitLab group would make the project's owner ambiguous."""
        db = _db(
            _team(),
            _team("team-2", "Platform", gitlab_instance_id="gl-1", gitlab_group_id=77),
        )

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db)

        assert excinfo.value.status_code == 409
        assert "Platform" in excinfo.value.detail
        assert "gitlab_group_id" not in _stored(db)

    def test_the_same_group_number_on_another_instance_is_a_different_binding(self):
        db = _db(
            _team(),
            _team("team-2", "Billing", gitlab_instance_id="gl-2", gitlab_group_id=77),
        )

        _run_bind(db)

        assert _stored(db)["gitlab_group_id"] == 77

    def test_rebinding_a_team_to_the_binding_it_already_holds_is_allowed(self):
        db = _db(_team(gitlab_instance_id="gl-1", gitlab_group_id=77, gitlab_group_path="mo/old"))

        _run_bind(db)

        assert _stored(db)["gitlab_group_path"] == "mo/edge"

    def test_a_binding_taken_between_the_check_and_the_write_is_a_conflict_not_a_crash(self):
        """The unique index is the only thing that can see a concurrent write; a 500 would tell
        the operator the binding failed for an unknown reason."""
        from app.api.v1.endpoints.teams import set_team_gitlab_binding

        team_repo = MagicMock()
        team_repo.get_raw_by_id = AsyncMock(return_value=_team())
        team_repo.get_raw_by_gitlab_group = AsyncMock(return_value=None)
        team_repo.update = AsyncMock(side_effect=DuplicateKeyError("E11000 duplicate key error"))
        instance_repo = MagicMock()
        instance_repo.get_by_id = AsyncMock(return_value=make_gitlab_instance(id="gl-1"))
        service = MagicMock()
        service.get_group = AsyncMock(return_value=_FOUND)

        with (
            patch(f"{MODULE}.TeamRepository", return_value=team_repo),
            patch(f"{MODULE}.GitLabInstanceRepository", return_value=instance_repo),
            patch(f"{MODULE}.GitLabService", return_value=service),
        ):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(
                    set_team_gitlab_binding(
                        team_id="team-1",
                        binding_in=_BINDING,
                        current_user=MagicMock(username="admin"),
                        db=MagicMock(),
                    )
                )

        assert excinfo.value.status_code == 409


class TestClearBinding:
    def _run(self, db, team_id="team-1"):
        from app.api.v1.endpoints.teams import clear_team_gitlab_binding

        return asyncio.run(
            clear_team_gitlab_binding(team_id=team_id, current_user=MagicMock(username="admin"), db=db)
        )

    def test_every_field_of_the_binding_is_nulled(self):
        """A mis-binding has to be reversible, and a half-cleared one still resolves."""
        db = _db(_team(gitlab_instance_id="gl-1", gitlab_group_id=77, gitlab_group_path="mo/edge"))

        response = self._run(db)

        stored = _stored(db)
        assert [
            stored["gitlab_instance_id"],
            stored["gitlab_group_id"],
            stored["gitlab_group_path"],
        ] == [None, None, None]
        assert response.gitlab_group_id is None

    def test_the_github_binding_is_left_alone(self):
        db = _db(
            _team(
                gitlab_instance_id="gl-1",
                gitlab_group_id=77,
                github_instance_id="gh-1",
                github_org="Acme",
                github_team_id=4711,
                github_team_slug="payments",
            )
        )

        response = self._run(db)

        assert response.github_team_id == 4711
        assert _stored(db)["github_team_slug"] == "payments"

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

    @pytest.mark.parametrize("method", ["PUT", "DELETE"])
    def test_both_binding_routes_demand_system_manage(self, method):
        assert self._required_permissions("/{team_id}/gitlab-binding", method) == [[Permissions.SYSTEM_MANAGE]]
