"""Composition tests for check_project_access: read_all is read-only, project:update is the write superuser, and effective role = MAX(direct, team)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
)
from app.core.permissions import Permissions
from app.models.project import Project, ProjectMember
from app.models.user import User

HELPERS_PROJECTS = "app.api.v1.helpers.projects"


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


def _run(user, *, required_role=None, project=None, team_doc=None):
    """Invoke check_project_access with mocked repos."""
    from app.api.v1.helpers.projects import check_project_access

    mock_proj_repo = MagicMock()
    mock_proj_repo.get_by_id = AsyncMock(return_value=project)

    mock_team_repo = MagicMock()
    mock_team_repo.get_raw_by_id = AsyncMock(return_value=team_doc)

    with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
        with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=mock_team_repo):
            return asyncio.run(
                check_project_access(
                    "proj-1",
                    user,
                    MagicMock(),
                    required_role=required_role,
                )
            )


class TestSeamAReadAllIsReadOnly:
    """project:read_all grants READ but NOT write."""

    def test_read_all_nonmember_read_access_granted(self):
        # User has read + read_all only, is NOT a member.
        user = _user("ra-1", [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL])
        project = _project(members=[])

        # No required_role => READ => allowed.
        result = _run(user, project=project)
        assert result.id == "proj-1"

        # required_role="viewer" is also READ => allowed.
        result = _run(user, required_role=PROJECT_ROLE_VIEWER, project=project)
        assert result.id == "proj-1"

    def test_read_all_nonmember_write_denied(self):
        # read_all alone must NOT satisfy a WRITE role for a non-member.
        user = _user("ra-2", [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL])
        project = _project(members=[])

        for role in (PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN):
            with pytest.raises(HTTPException) as exc_info:
                _run(user, required_role=role, project=project)
            assert exc_info.value.status_code == 403


class TestSeamBNoDowngrade:
    """effective role = MAX(direct, team) — never downgraded."""

    def test_direct_editor_plus_team_member_keeps_editor(self):
        user = _user("ed-1", [Permissions.PROJECT_READ])
        project = _project(
            members=[ProjectMember(user_id=str(user.id), role=PROJECT_ROLE_EDITOR)],
            team_id="team-1",
        )
        # Plain team member would map to viewer — must NOT downgrade the editor.
        team_doc = {
            "_id": "team-1",
            "members": [{"user_id": str(user.id), "role": TEAM_ROLE_MEMBER}],
        }

        result = _run(user, required_role=PROJECT_ROLE_EDITOR, project=project, team_doc=team_doc)
        assert result.id == "proj-1"

    def test_team_admin_upgrades_direct_viewer(self):
        # The MAX rule should also upgrade: direct viewer + team admin => admin.
        user = _user("up-1", [Permissions.PROJECT_READ])
        project = _project(
            members=[ProjectMember(user_id=str(user.id), role=PROJECT_ROLE_VIEWER)],
            team_id="team-1",
        )
        team_doc = {
            "_id": "team-1",
            "members": [{"user_id": str(user.id), "role": TEAM_ROLE_ADMIN}],
        }
        result = _run(user, required_role=PROJECT_ROLE_ADMIN, project=project, team_doc=team_doc)
        assert result.id == "proj-1"


class TestSeamCWriteSuperuser:
    """project:update is the uniform write superuser."""

    def test_project_update_nonmember_passes_write(self):
        # project:update holder, NOT a member, passes editor + admin writes.
        user = _user("pu-1", [Permissions.PROJECT_READ, Permissions.PROJECT_UPDATE])
        project = _project(members=[])

        for role in (PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN):
            result = _run(user, required_role=role, project=project)
            assert result.id == "proj-1"

    def test_project_update_nonmember_passes_read(self):
        # Write superuser should also be allowed to read.
        user = _user("pu-2", [Permissions.PROJECT_READ, Permissions.PROJECT_UPDATE])
        project = _project(members=[])
        result = _run(user, project=project)
        assert result.id == "proj-1"

    def test_nonmember_without_update_denied_write(self):
        # Only project:read (no read_all, no update), non-member => write denied.
        user = _user("nm-1", [Permissions.PROJECT_READ])
        project = _project(members=[])
        for role in (PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN):
            with pytest.raises(HTTPException) as exc_info:
                _run(user, required_role=role, project=project)
            assert exc_info.value.status_code == 403


class TestRegressions:
    """Existing behaviour that must keep working."""

    def test_real_admin_manages_any_project(self):
        from tests.helpers.permission_presets import PRESET_ADMIN

        user = _user("admin-1", PRESET_ADMIN)
        project = _project(members=[])
        # Read and every write role pass for a full admin (read_all + update).
        assert _run(user, project=project).id == "proj-1"
        for role in (PROJECT_ROLE_VIEWER, PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN):
            assert _run(user, required_role=role, project=project).id == "proj-1"

    def test_project_admin_member_passes(self):
        user = _user("pa-1", [Permissions.PROJECT_READ])
        project = _project(members=[ProjectMember(user_id=str(user.id), role=PROJECT_ROLE_ADMIN)])
        assert _run(user, required_role=PROJECT_ROLE_ADMIN, project=project).id == "proj-1"

    def test_viewer_denied_editor_and_admin(self):
        user = _user("vw-1", [Permissions.PROJECT_READ])
        project = _project(members=[ProjectMember(user_id=str(user.id), role=PROJECT_ROLE_VIEWER)])
        for role in (PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN):
            with pytest.raises(HTTPException) as exc_info:
                _run(user, required_role=role, project=project)
            assert exc_info.value.status_code == 403

    def test_member_without_read_feature_gate_denied(self):
        # feature gate: a member lacking project:read is denied.
        user = _user("ng-1", [])
        project = _project(members=[ProjectMember(user_id=str(user.id), role=PROJECT_ROLE_VIEWER)])
        with pytest.raises(HTTPException) as exc_info:
            _run(user, project=project)
        assert exc_info.value.status_code == 403
