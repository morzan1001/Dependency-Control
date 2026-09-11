"""Binding a team to a GitHub team: the only writer of the fields resolution reads."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError

from app.api.deps import PermissionChecker
from app.core.permissions import Permissions
from app.schemas.team import TeamGitHubBindingUpdate
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance

MODULE = "app.api.v1.endpoints.teams"
_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)

_ORG_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "parent": None},
    {"id": 900, "slug": "cards", "name": "Cards", "parent": {"id": 4711, "slug": "payments"}},
]

_BINDING = TeamGitHubBindingUpdate(github_instance_id="gh-1", github_org="Acme", github_team_id=4711)


def _db(*teams) -> FakeDatabase:
    db = FakeDatabase()
    for team in teams:
        db.teams._docs[team["_id"]] = team
    return db


def _team(team_id: str = "team-1", name: str = "Payments Guild", **binding) -> dict:
    return {
        "_id": team_id,
        "name": name,
        "members": [],
        "created_at": _TIMESTAMP,
        "updated_at": _TIMESTAMP,
        **binding,
    }


def _run_bind(db, binding=_BINDING, *, org_teams=_ORG_TEAMS, team_id="team-1", user=None):
    from app.api.v1.endpoints.teams import set_team_github_binding

    instance_repo = MagicMock()
    instance_repo.get_by_id = AsyncMock(return_value=make_github_instance(id="gh-1", access_token="ghp-secret"))
    service = MagicMock()
    service.get_org_teams = AsyncMock(return_value=org_teams)

    with (
        patch(f"{MODULE}.GitHubInstanceRepository", return_value=instance_repo),
        patch(f"{MODULE}.GitHubService", return_value=service),
    ):
        return asyncio.run(
            set_team_github_binding(
                team_id=team_id,
                binding_in=binding,
                current_user=user or MagicMock(username="admin"),
                db=db,
            )
        )


def _stored(db, team_id="team-1") -> dict:
    return db.teams._docs[team_id]


class TestSetBinding:
    def test_the_four_fields_resolution_reads_are_written(self):
        db = _db(_team())

        response = _run_bind(db)

        assert _stored(db)["github_instance_id"] == "gh-1"
        assert _stored(db)["github_org"] == "Acme"
        assert _stored(db)["github_team_id"] == 4711
        assert response.github_team_id == 4711

    def test_the_slug_comes_from_the_organisation_listing_not_from_the_caller(self):
        """A slug the caller invented would address whichever team took that name."""
        db = _db(_team())

        _run_bind(db, TeamGitHubBindingUpdate(github_instance_id="gh-1", github_org="Acme", github_team_id=900))

        assert _stored(db)["github_team_slug"] == "cards"

    def test_a_team_the_organisation_does_not_list_is_refused(self):
        """Binding a number no organisation carries stores a binding that resolves nothing, silently."""
        db = _db(_team())
        unknown = TeamGitHubBindingUpdate(github_instance_id="gh-1", github_org="Acme", github_team_id=6666)

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, unknown)

        assert excinfo.value.status_code == 400
        assert "github_team_id" not in _stored(db)

    def test_an_unreadable_organisation_is_a_bad_gateway_rather_than_a_guess(self):
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, org_teams=None)

        assert excinfo.value.status_code == 502
        assert "github_team_id" not in _stored(db)

    def test_an_unknown_team_is_not_found(self):
        db = _db(_team())

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db, team_id="team-absent")

        assert excinfo.value.status_code == 404

    def test_an_unknown_instance_is_not_found(self):
        from app.api.v1.endpoints.teams import set_team_github_binding

        db = _db(_team())
        instance_repo = MagicMock()
        instance_repo.get_by_id = AsyncMock(return_value=None)

        with patch(f"{MODULE}.GitHubInstanceRepository", return_value=instance_repo):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(
                    set_team_github_binding(
                        team_id="team-1",
                        binding_in=_BINDING,
                        current_user=MagicMock(username="admin"),
                        db=db,
                    )
                )

        assert excinfo.value.status_code == 404
        assert "github_team_id" not in _stored(db)


class TestBindingUniqueness:
    def test_a_github_team_another_team_already_holds_is_refused(self):
        """Two teams bound to one GitHub team would make the repository's owner ambiguous."""
        db = _db(
            _team(),
            _team("team-2", "Payments", github_instance_id="gh-1", github_org="acme", github_team_id=4711),
        )

        with pytest.raises(HTTPException) as excinfo:
            _run_bind(db)

        assert excinfo.value.status_code == 409
        assert "Payments" in excinfo.value.detail
        assert "github_team_id" not in _stored(db)

    def test_the_same_team_number_on_another_instance_is_a_different_binding(self):
        db = _db(
            _team(),
            _team("team-2", "Billing", github_instance_id="gh-2", github_org="acme", github_team_id=4711),
        )

        _run_bind(db)

        assert _stored(db)["github_team_id"] == 4711

    def test_rebinding_a_team_to_the_binding_it_already_holds_is_allowed(self):
        db = _db(_team(github_instance_id="gh-1", github_org="Acme", github_team_id=4711, github_team_slug="pay-old"))

        _run_bind(db)

        assert _stored(db)["github_team_slug"] == "payments"

    def test_a_binding_taken_between_the_check_and_the_write_is_a_conflict_not_a_crash(self):
        """The unique index is the only thing that can see a concurrent write; a 500 would tell
        the operator the binding failed for an unknown reason."""
        from app.api.v1.endpoints.teams import set_team_github_binding

        team_repo = MagicMock()
        team_repo.get_raw_by_id = AsyncMock(return_value=_team())
        team_repo.get_raw_by_github_team = AsyncMock(return_value=None)
        team_repo.update = AsyncMock(side_effect=DuplicateKeyError("E11000 duplicate key error"))
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
                    set_team_github_binding(
                        team_id="team-1",
                        binding_in=_BINDING,
                        current_user=MagicMock(username="admin"),
                        db=MagicMock(),
                    )
                )

        assert excinfo.value.status_code == 409


class TestClearBinding:
    def _run(self, db, team_id="team-1"):
        from app.api.v1.endpoints.teams import clear_team_github_binding

        return asyncio.run(
            clear_team_github_binding(team_id=team_id, current_user=MagicMock(username="admin"), db=db)
        )

    def test_every_field_of_the_binding_is_nulled(self):
        """A mis-binding has to be reversible, and a half-cleared one still resolves."""
        db = _db(
            _team(
                github_instance_id="gh-1",
                github_org="Acme",
                github_team_id=4711,
                github_team_slug="payments",
            )
        )

        response = self._run(db)

        stored = _stored(db)
        assert [
            stored["github_instance_id"],
            stored["github_org"],
            stored["github_team_id"],
            stored["github_team_slug"],
        ] == [None, None, None, None]
        assert response.github_team_id is None

    def test_an_unknown_team_is_not_found(self):
        with pytest.raises(HTTPException) as excinfo:
            self._run(_db(_team()), team_id="team-absent")

        assert excinfo.value.status_code == 404


class TestBindingIsGatedOnSystemManage:
    """A binding decides which repositories of the estate land in the team, and team membership
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
        assert self._required_permissions("/{team_id}/github-binding", method) == [[Permissions.SYSTEM_MANAGE]]
