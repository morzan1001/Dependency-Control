"""Endpoint-level authz tests for the project write paths: every write path routes through check_project_access(required_role="admin"), so a project:update holder passes all and a plain reader is denied 403."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.core.permissions import Permissions
from app.models.project import Project
from app.models.user import User

ENDPOINTS = "app.api.v1.endpoints.projects"


def _user(uid: str, permissions):
    return User(
        id=uid,
        username=uid,
        email=f"{uid}@test.com",
        permissions=list(permissions),
    )


def _project(members=None, team_ids=None):
    return Project(
        id="proj-1",
        name="Test",
        owner_id="owner-x",
        members=members or [],
        team_ids=team_ids or [],
    )


def _update_user():
    """Non-member who holds the write superuser permission."""
    return _user("pu-1", [Permissions.PROJECT_READ, Permissions.PROJECT_UPDATE])


def _delete_only_user():
    """Non-member who holds ONLY project:delete (a write superuser too)."""
    return _user("pd-1", [Permissions.PROJECT_DELETE])


def _plain_member():
    """Non-member with only project:read (no write superuser)."""
    return _user("nm-1", [Permissions.PROJECT_READ])


class TestRotateApiKeyRoutesThroughGate:
    def test_update_holder_routes_through_gate(self):
        from app.api.v1.endpoints.projects import rotate_api_key

        user = _update_user()
        project = _project(members=[])

        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=project)
        mock_repo.update = AsyncMock(return_value=None)

        with patch(f"{ENDPOINTS}.ProjectRepository", return_value=mock_repo):
            with patch(f"{ENDPOINTS}.check_project_access", new_callable=AsyncMock, return_value=project) as mock_gate:
                result = asyncio.run(rotate_api_key("proj-1", user, MagicMock()))

        # The gate must be invoked at admin level even for a project:update holder.
        mock_gate.assert_awaited_once()
        assert mock_gate.call_args.kwargs.get("required_role") == "admin"
        assert result.project_id == "proj-1"

    def test_nonmember_without_update_denied(self):
        from app.api.v1.endpoints.projects import rotate_api_key

        user = _plain_member()
        mock_repo = MagicMock()

        with (
            patch(f"{ENDPOINTS}.ProjectRepository", return_value=mock_repo),
            patch(
                f"{ENDPOINTS}.check_project_access",
                new_callable=AsyncMock,
                side_effect=HTTPException(status_code=403, detail="nope"),
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(rotate_api_key("proj-1", user, MagicMock()))
        assert exc_info.value.status_code == 403


class TestLoadProjectForUpdateRoutesThroughGate:
    def test_update_holder_routes_through_gate(self):
        from app.api.v1.endpoints.projects import _load_project_for_update

        user = _update_user()
        project = _project(members=[])

        with patch(f"{ENDPOINTS}.check_project_access", new_callable=AsyncMock, return_value=project) as mock_gate:
            result = asyncio.run(_load_project_for_update("proj-1", user, MagicMock()))

        mock_gate.assert_awaited_once()
        assert mock_gate.call_args.kwargs.get("required_role") == "admin"
        assert result.id == "proj-1"

    def test_nonmember_without_update_denied(self):
        from app.api.v1.endpoints.projects import _load_project_for_update

        user = _plain_member()

        with (
            patch(
                f"{ENDPOINTS}.check_project_access",
                new_callable=AsyncMock,
                side_effect=HTTPException(status_code=403, detail="nope"),
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(_load_project_for_update("proj-1", user, MagicMock()))
        assert exc_info.value.status_code == 403


class TestTransferTeamSuperuser:
    @staticmethod
    def _hand_over(user, project, team_repo, team_id="new-team"):
        from app.api.v1.endpoints.projects import _assert_may_hand_to_team

        team_repo.get_by_id = AsyncMock(return_value={"_id": team_id})
        return asyncio.run(_assert_may_hand_to_team(project, team_id, user, team_repo))

    def test_update_holder_can_transfer_without_target_membership(self):
        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=False)

        # project:update bypasses target-team membership.
        self._hand_over(_update_user(), _project(team_ids=["old-team"]), team_repo)
        team_repo.is_member.assert_not_called()

    def test_delete_only_holder_can_transfer_without_target_membership(self):
        """project:delete is part of the write-superuser set, so a delete-only non-member may also transfer the team."""
        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=False)

        self._hand_over(_delete_only_user(), _project(team_ids=["old-team"]), team_repo)
        team_repo.is_member.assert_not_called()

    def test_nonmember_without_update_denied_transfer(self):
        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=False)

        with pytest.raises(HTTPException) as exc_info:
            self._hand_over(_plain_member(), _project(team_ids=["old-team"]), team_repo)
        assert exc_info.value.status_code == 403

    def test_a_team_that_already_owns_the_project_is_no_transfer_at_all(self):
        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=False)

        self._hand_over(_plain_member(), _project(team_ids=["old-team"]), team_repo, team_id="old-team")
        team_repo.is_member.assert_not_called()

    def test_the_owner_cap_stops_even_a_superuser(self):
        from app.core.constants import MAX_PROJECT_TEAMS

        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=True)
        project = _project(team_ids=[f"t-{n}" for n in range(MAX_PROJECT_TEAMS)])

        with pytest.raises(HTTPException) as exc_info:
            self._hand_over(_update_user(), project, team_repo)
        assert exc_info.value.status_code == 400


class TestDeleteProjectRoutesThroughGate:
    def test_update_holder_routes_through_gate(self):
        from app.api.v1.endpoints.projects import delete_project

        user = _update_user()
        project = _project(members=[])

        repos = {
            "ProjectRepository": MagicMock(),
            "ScanRepository": MagicMock(),
            "WaiverRepository": MagicMock(),
            "ReleaseRepository": MagicMock(),
            "InvitationRepository": MagicMock(),
            "CallgraphRepository": MagicMock(),
        }
        scan_repo = repos["ScanRepository"]

        async def _empty_iter(*args, **kwargs):
            return
            yield  # pragma: no cover

        scan_repo.iterate = _empty_iter
        repos["WaiverRepository"].delete_many = AsyncMock(return_value=None)
        repos["ReleaseRepository"].delete_many = AsyncMock(return_value=None)
        repos["InvitationRepository"].delete_project_invitations_by_project = AsyncMock(return_value=None)
        repos["CallgraphRepository"].delete_by_project = AsyncMock(return_value=None)
        repos["ProjectRepository"].delete = AsyncMock(return_value=None)

        patches = [patch(f"{ENDPOINTS}.{name}", return_value=repo) for name, repo in repos.items()]
        gate = patch(f"{ENDPOINTS}.check_project_access", new_callable=AsyncMock, return_value=project)
        cascade = patch(f"{ENDPOINTS}.delete_scans_and_related_data", new_callable=AsyncMock, return_value=0)

        with gate as mock_gate, cascade:
            for p in patches:
                p.start()
            try:
                asyncio.run(delete_project("proj-1", user, MagicMock()))
            finally:
                for p in patches:
                    p.stop()

        mock_gate.assert_awaited_once()
        assert mock_gate.call_args.kwargs.get("required_role") == "admin"

    def test_nonmember_without_update_denied(self):
        from app.api.v1.endpoints.projects import delete_project

        user = _plain_member()

        with (
            patch(
                f"{ENDPOINTS}.check_project_access",
                new_callable=AsyncMock,
                side_effect=HTTPException(status_code=403, detail="nope"),
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
            asyncio.run(delete_project("proj-1", user, MagicMock()))
        assert exc_info.value.status_code == 403


class TestUpdateProjectTeamAssignment:
    """team_id on the update body is the caller's own assignment: it replaces the owners marked
    manual and leaves a provider's entry to that provider."""

    def _build_update_project_mocks(self, project: "Project"):
        """Return the mocked collaborators for update_project."""
        project_repo = MagicMock()
        project_repo.update_raw = AsyncMock(return_value=True)
        project_repo.get_by_id_strong = AsyncMock(return_value=project)

        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=True)

        system_settings = MagicMock()
        system_settings.retention_mode = None
        system_settings.rescan_mode = None

        return project_repo, team_repo, system_settings

    def _run_update(self, project, project_in, user):
        """Drive update_project with all external collaborators mocked out."""
        from app.api.v1.endpoints.projects import update_project

        project_repo, team_repo, system_settings = self._build_update_project_mocks(project)

        with (
            patch(f"{ENDPOINTS}.ProjectRepository", return_value=project_repo),
            patch(f"{ENDPOINTS}.TeamRepository", return_value=team_repo),
            patch(f"{ENDPOINTS}._load_project_for_update", new_callable=AsyncMock, return_value=project),
            patch(f"{ENDPOINTS}._assert_may_hand_to_team", new_callable=AsyncMock),
            patch(f"{ENDPOINTS}._assert_gitlab_mr_token_present", new_callable=AsyncMock),
            patch(f"{ENDPOINTS}.deps.get_system_settings", new_callable=AsyncMock, return_value=system_settings),
            patch(f"{ENDPOINTS}.apply_system_settings_enforcement", side_effect=lambda d, *_: d),
            patch(f"{ENDPOINTS}._audit_license_policy_change", new_callable=AsyncMock),
        ):
            asyncio.run(update_project("proj-1", project_in, user, MagicMock()))

        return project_repo.update_raw

    @staticmethod
    def _project_owned_by_gitlab():
        return Project(
            id="proj-1",
            name="Test",
            owner_id="owner-x",
            members=[],
            team_ids=["team-abc"],
            team_sources={"team-abc": "gitlab"},
            team_id="team-abc",
            team_source="gitlab",
        )

    def test_a_team_in_the_body_replaces_the_manual_owners_only(self):
        from app.repositories.projects import literal_set_stage, replace_team_subset_pipeline
        from app.schemas.project import ProjectUpdate

        mock_update = self._run_update(
            self._project_owned_by_gitlab(), ProjectUpdate(name="Renamed", team_id="team-xyz"), _update_user()
        )

        mock_update.assert_awaited_once()
        assert mock_update.call_args[0][1] == [
            literal_set_stage({"name": "Renamed"}),
            *replace_team_subset_pipeline("manual", ["team-xyz"]),
        ]

    def test_a_null_team_gives_up_the_manual_assignment_and_keeps_the_provider_s(self):
        from app.repositories.projects import replace_team_subset_pipeline
        from app.schemas.project import ProjectUpdate

        mock_update = self._run_update(
            self._project_owned_by_gitlab(), ProjectUpdate(team_id=None), _update_user()
        )

        mock_update.assert_awaited_once()
        assert mock_update.call_args[0][1] == replace_team_subset_pipeline("manual", [])

    def test_a_body_without_a_team_leaves_every_owner_alone(self):
        from app.repositories.projects import literal_set_stage
        from app.schemas.project import ProjectUpdate

        mock_update = self._run_update(
            self._project_owned_by_gitlab(), ProjectUpdate(name="Only a rename"), _update_user()
        )

        mock_update.assert_awaited_once()
        assert mock_update.call_args[0][1] == [literal_set_stage({"name": "Only a rename"})]
