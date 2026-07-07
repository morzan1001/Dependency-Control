"""Endpoint-level authz tests for the project WRITE paths (Finding 22 / W2).

These verify the duplicated inline ``project:update`` bypass blocks have been
removed and every write path now routes uniformly through
``check_project_access(required_role="admin")``:

* ``rotate_api_key``
* ``update_project`` (via ``_load_project_for_update``)
* team transfer (via ``_assert_can_transfer_team``)
* ``delete_project``

A ``project:update`` holder (non-member) must pass all of them identically;
a non-member without it must be denied (403) by the gate.
"""

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


def _project(members=None, team_id=None):
    return Project(
        id="proj-1",
        name="Test",
        owner_id="owner-x",
        members=members or [],
        team_id=team_id,
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

        with patch(f"{ENDPOINTS}.ProjectRepository", return_value=mock_repo):
            with patch(
                f"{ENDPOINTS}.check_project_access",
                new_callable=AsyncMock,
                side_effect=HTTPException(status_code=403, detail="nope"),
            ):
                with pytest.raises(HTTPException) as exc_info:
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

        with patch(
            f"{ENDPOINTS}.check_project_access",
            new_callable=AsyncMock,
            side_effect=HTTPException(status_code=403, detail="nope"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(_load_project_for_update("proj-1", user, MagicMock()))
        assert exc_info.value.status_code == 403


class TestTransferTeamSuperuser:
    def test_update_holder_can_transfer_without_target_membership(self):
        from app.api.v1.endpoints.projects import _assert_can_transfer_team
        from app.schemas.project import ProjectUpdate

        user = _update_user()
        project = _project(team_id="old-team")
        project_in = ProjectUpdate(team_id="new-team")

        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=False)

        # Should NOT raise — project:update bypasses target-team membership.
        asyncio.run(_assert_can_transfer_team(project, project_in, user, team_repo))
        team_repo.is_member.assert_not_called()

    def test_delete_only_holder_can_transfer_without_target_membership(self):
        """A non-member with ONLY project:delete is a write superuser too, so it
        must be allowed to transfer the team — parity with the gate's
        ``_WRITE_SUPERUSER_PERMISSIONS`` set (PROJECT_UPDATE *and* PROJECT_DELETE).
        """
        from app.api.v1.endpoints.projects import _assert_can_transfer_team
        from app.schemas.project import ProjectUpdate

        user = _delete_only_user()
        project = _project(team_id="old-team")
        project_in = ProjectUpdate(team_id="new-team")

        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=False)

        # Should NOT raise — project:delete is part of the write-superuser set.
        asyncio.run(_assert_can_transfer_team(project, project_in, user, team_repo))
        team_repo.is_member.assert_not_called()

    def test_nonmember_without_update_denied_transfer(self):
        from app.api.v1.endpoints.projects import _assert_can_transfer_team
        from app.schemas.project import ProjectUpdate

        user = _plain_member()
        project = _project(team_id="old-team")
        project_in = ProjectUpdate(team_id="new-team")

        team_repo = MagicMock()
        team_repo.is_member = AsyncMock(return_value=False)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(_assert_can_transfer_team(project, project_in, user, team_repo))
        assert exc_info.value.status_code == 403


class TestDeleteProjectRoutesThroughGate:
    def test_update_holder_routes_through_gate(self):
        from app.api.v1.endpoints.projects import delete_project

        # A project:update holder, non-member, must be able to delete via the gate.
        user = _update_user()
        project = _project(members=[])

        repos = {
            "ProjectRepository": MagicMock(),
            "ScanRepository": MagicMock(),
            "AnalysisResultRepository": MagicMock(),
            "FindingRepository": MagicMock(),
            "DependencyRepository": MagicMock(),
            "WaiverRepository": MagicMock(),
            "InvitationRepository": MagicMock(),
            "CallgraphRepository": MagicMock(),
        }
        # Configure the async methods used by delete_project.
        scan_repo = repos["ScanRepository"]

        async def _empty_iter(*args, **kwargs):
            return
            yield  # pragma: no cover

        scan_repo.iterate = _empty_iter
        scan_repo.delete_many = AsyncMock(return_value=None)
        repos["AnalysisResultRepository"].delete_many = AsyncMock(return_value=None)
        repos["FindingRepository"].delete_many = AsyncMock(return_value=None)
        repos["DependencyRepository"].delete_many = AsyncMock(return_value=None)
        repos["WaiverRepository"].delete_many = AsyncMock(return_value=None)
        repos["InvitationRepository"].delete_project_invitations_by_project = AsyncMock(return_value=None)
        repos["CallgraphRepository"].delete_by_project = AsyncMock(return_value=None)
        repos["ProjectRepository"].delete = AsyncMock(return_value=None)

        patches = [patch(f"{ENDPOINTS}.{name}", return_value=repo) for name, repo in repos.items()]
        gate = patch(f"{ENDPOINTS}.check_project_access", new_callable=AsyncMock, return_value=project)
        gridfs = patch(f"{ENDPOINTS}.delete_gridfs_files", new_callable=AsyncMock, return_value=None)

        with gate as mock_gate, gridfs:
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

        with patch(
            f"{ENDPOINTS}.check_project_access",
            new_callable=AsyncMock,
            side_effect=HTTPException(status_code=403, detail="nope"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(delete_project("proj-1", user, MagicMock()))
        assert exc_info.value.status_code == 403


class TestUpdateProjectTeamSourceProvenance:
    """W9: stamping team_source='manual' must only happen when team_id actually changes.

    A frontend that echoes back the current (sync-assigned) team_id on any
    unrelated edit must NOT flip provenance to 'manual' and opt the project out
    of GitLab-sync-managed assignment.
    """

    def _build_update_project_mocks(self, project: "Project"):
        """Return a context-manager stack that patches update_project's collaborators."""
        project_repo = MagicMock()
        project_repo.update = AsyncMock(return_value=None)
        project_repo.get_by_id = AsyncMock(return_value=project)

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
            patch(f"{ENDPOINTS}._assert_can_transfer_team", new_callable=AsyncMock),
            patch(f"{ENDPOINTS}._assert_gitlab_mr_token_present", new_callable=AsyncMock),
            patch(f"{ENDPOINTS}.deps.get_system_settings", new_callable=AsyncMock, return_value=system_settings),
            patch(f"{ENDPOINTS}.apply_system_settings_enforcement", side_effect=lambda d, *_: d),
            patch(f"{ENDPOINTS}._audit_license_policy_change", new_callable=AsyncMock),
        ):
            asyncio.run(update_project("proj-1", project_in, user, MagicMock()))

        return project_repo.update

    def test_same_team_id_does_not_stamp_manual(self):
        """PATCHing with the SAME team_id as the current project must leave team_source unchanged (W9)."""
        from app.schemas.project import ProjectUpdate

        # A gitlab-synced project has team_source="gitlab"
        project = Project(
            id="proj-1",
            name="Test",
            owner_id="owner-x",
            members=[],
            team_id="team-abc",
            team_source="gitlab",
        )
        user = _update_user()
        # Frontend echoes back the same team_id it already has
        project_in = ProjectUpdate(name="Renamed", team_id="team-abc")

        mock_update = self._run_update(project, project_in, user)

        # update must have been called
        mock_update.assert_awaited_once()
        call_kwargs = mock_update.call_args[0][1]  # second positional arg is the update dict
        assert "team_source" not in call_kwargs, "team_source must NOT be written when team_id is unchanged"

    def test_different_team_id_stamps_manual(self):
        """PATCHing with a DIFFERENT team_id must set team_source='manual' (W9)."""
        from app.schemas.project import ProjectUpdate

        project = Project(
            id="proj-1",
            name="Test",
            owner_id="owner-x",
            members=[],
            team_id="team-abc",
            team_source="gitlab",
        )
        user = _update_user()
        project_in = ProjectUpdate(team_id="team-xyz")

        mock_update = self._run_update(project, project_in, user)

        mock_update.assert_awaited_once()
        call_kwargs = mock_update.call_args[0][1]
        assert call_kwargs.get("team_source") == "manual", "team_source must be set to 'manual' when team_id changes"

    def test_no_team_id_in_payload_does_not_stamp_manual(self):
        """PATCHing with no team_id field at all must not touch team_source (W9)."""
        from app.schemas.project import ProjectUpdate

        project = Project(
            id="proj-1",
            name="Test",
            owner_id="owner-x",
            members=[],
            team_id="team-abc",
            team_source="gitlab",
        )
        user = _update_user()
        project_in = ProjectUpdate(name="Only a rename")

        mock_update = self._run_update(project, project_in, user)

        mock_update.assert_awaited_once()
        call_kwargs = mock_update.call_args[0][1]
        assert "team_source" not in call_kwargs
