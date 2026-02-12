"""Tests for permission helper functions."""

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
    TEAM_ROLE_OWNER,
)
from app.models.project import Project, ProjectMember
from app.models.team import Team, TeamMember
from app.models.webhook import Webhook

HELPERS_TEAMS = "app.api.v1.helpers.teams"
HELPERS_PROJECTS = "app.api.v1.helpers.projects"
HELPERS_WEBHOOKS = "app.api.v1.helpers.webhooks"


class TestCheckProjectAccess:
    """Tests for check_project_access — the primary project security gate."""

    def _make_project(self, owner_id="owner-1", members=None, team_id=None):
        return Project(
            id="proj-1",
            name="Test",
            owner_id=owner_id,
            members=members or [],
            team_id=team_id,
        )

    def test_raises_404_when_project_not_found(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=None)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository"):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        check_project_access(
                            "nonexistent",
                            regular_user,
                            MagicMock(),
                        )
                    )
        assert exc_info.value.status_code == 404

    def test_admin_with_read_all_bypasses_all_checks(self, admin_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(owner_id="someone-else")
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository"):
                result = asyncio.run(
                    check_project_access(
                        "proj-1",
                        admin_user,
                        MagicMock(),
                    )
                )
        assert result.id == "proj-1"

    def test_owner_has_full_access(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(owner_id=str(regular_user.id))
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=MagicMock()):
                result = asyncio.run(
                    check_project_access(
                        "proj-1",
                        regular_user,
                        MagicMock(),
                    )
                )
        assert result.id == "proj-1"

    def test_owner_bypasses_role_check(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(owner_id=str(regular_user.id))
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=MagicMock()):
                # Owner can access even with admin role required
                result = asyncio.run(
                    check_project_access(
                        "proj-1",
                        regular_user,
                        MagicMock(),
                        required_role=PROJECT_ROLE_ADMIN,
                    )
                )
        assert result.id == "proj-1"

    def test_direct_member_viewer_gets_access(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(
            owner_id="other",
            members=[ProjectMember(user_id=str(regular_user.id), role=PROJECT_ROLE_VIEWER)],
        )
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=MagicMock()):
                result = asyncio.run(
                    check_project_access(
                        "proj-1",
                        regular_user,
                        MagicMock(),
                    )
                )
        assert result.id == "proj-1"

    def test_viewer_member_denied_editor_role(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(
            owner_id="other",
            members=[ProjectMember(user_id=str(regular_user.id), role=PROJECT_ROLE_VIEWER)],
        )
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=MagicMock()):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        check_project_access(
                            "proj-1",
                            regular_user,
                            MagicMock(),
                            required_role=PROJECT_ROLE_EDITOR,
                        )
                    )
        assert exc_info.value.status_code == 403

    def test_editor_member_can_access_editor_role(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(
            owner_id="other",
            members=[ProjectMember(user_id=str(regular_user.id), role=PROJECT_ROLE_EDITOR)],
        )
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=MagicMock()):
                result = asyncio.run(
                    check_project_access(
                        "proj-1",
                        regular_user,
                        MagicMock(),
                        required_role=PROJECT_ROLE_EDITOR,
                    )
                )
        assert result.id == "proj-1"

    def test_editor_member_denied_admin_role(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(
            owner_id="other",
            members=[ProjectMember(user_id=str(regular_user.id), role=PROJECT_ROLE_EDITOR)],
        )
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=MagicMock()):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        check_project_access(
                            "proj-1",
                            regular_user,
                            MagicMock(),
                            required_role=PROJECT_ROLE_ADMIN,
                        )
                    )
        assert exc_info.value.status_code == 403

    def test_non_member_denied_access(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(owner_id="other", members=[])
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        mock_team_repo = MagicMock()
        mock_team_repo.get_raw_by_id = AsyncMock(return_value=None)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=mock_team_repo):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        check_project_access(
                            "proj-1",
                            regular_user,
                            MagicMock(),
                        )
                    )
        assert exc_info.value.status_code == 403

    def test_team_admin_gets_project_admin_role(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(owner_id="other", team_id="team-1")
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        team_doc = {
            "_id": "team-1",
            "members": [{"user_id": str(regular_user.id), "role": TEAM_ROLE_ADMIN}],
        }
        mock_team_repo = MagicMock()
        mock_team_repo.get_raw_by_id = AsyncMock(return_value=team_doc)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=mock_team_repo):
                result = asyncio.run(
                    check_project_access(
                        "proj-1",
                        regular_user,
                        MagicMock(),
                        required_role=PROJECT_ROLE_ADMIN,
                    )
                )
        assert result.id == "proj-1"

    def test_team_member_gets_viewer_role(self, regular_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(owner_id="other", team_id="team-1")
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        team_doc = {
            "_id": "team-1",
            "members": [{"user_id": str(regular_user.id), "role": TEAM_ROLE_MEMBER}],
        }
        mock_team_repo = MagicMock()
        mock_team_repo.get_raw_by_id = AsyncMock(return_value=team_doc)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=mock_team_repo):
                # Team member can view...
                result = asyncio.run(
                    check_project_access(
                        "proj-1",
                        regular_user,
                        MagicMock(),
                    )
                )
                assert result.id == "proj-1"

                # ...but cannot access as editor
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        check_project_access(
                            "proj-1",
                            regular_user,
                            MagicMock(),
                            required_role=PROJECT_ROLE_EDITOR,
                        )
                    )
                assert exc_info.value.status_code == 403

    def test_user_without_project_read_denied(self, no_perms_user):
        from app.api.v1.helpers.projects import check_project_access

        project = self._make_project(
            owner_id="other",
            members=[ProjectMember(user_id=str(no_perms_user.id), role=PROJECT_ROLE_VIEWER)],
        )
        mock_proj_repo = MagicMock()
        mock_proj_repo.get_by_id = AsyncMock(return_value=project)

        with patch(f"{HELPERS_PROJECTS}.ProjectRepository", return_value=mock_proj_repo):
            with patch(f"{HELPERS_PROJECTS}.TeamRepository", return_value=MagicMock()):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        check_project_access(
                            "proj-1",
                            no_perms_user,
                            MagicMock(),
                        )
                    )
        assert exc_info.value.status_code == 403


class TestCheckTeamAccess:
    """Tests for check_team_access — the primary team security gate."""

    def _make_team(self, members=None):
        return Team(
            id="team-1",
            name="Test Team",
            members=members or [],
        )

    def test_raises_404_when_team_not_found(self, regular_user):
        from app.api.v1.helpers.teams import check_team_access

        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=None)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    check_team_access(
                        "nonexistent",
                        regular_user,
                        MagicMock(),
                    )
                )
        assert exc_info.value.status_code == 404

    def test_admin_with_read_all_bypasses_membership(self, admin_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(members=[])  # No members
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            result = asyncio.run(
                check_team_access(
                    "team-1",
                    admin_user,
                    MagicMock(),
                )
            )
        assert result.id == "team-1"

    def test_member_gets_access(self, regular_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(
            members=[TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_MEMBER)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            result = asyncio.run(
                check_team_access(
                    "team-1",
                    regular_user,
                    MagicMock(),
                )
            )
        assert result.id == "team-1"

    def test_non_member_denied(self, regular_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(
            members=[TeamMember(user_id="other-user", role=TEAM_ROLE_OWNER)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    check_team_access(
                        "team-1",
                        regular_user,
                        MagicMock(),
                    )
                )
        assert exc_info.value.status_code == 403

    def test_member_role_insufficient(self, regular_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(
            members=[TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_MEMBER)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    check_team_access(
                        "team-1",
                        regular_user,
                        MagicMock(),
                        required_role=TEAM_ROLE_ADMIN,
                    )
                )
        assert exc_info.value.status_code == 403

    def test_admin_role_sufficient_for_admin_required(self, regular_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(
            members=[TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_ADMIN)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            result = asyncio.run(
                check_team_access(
                    "team-1",
                    regular_user,
                    MagicMock(),
                    required_role=TEAM_ROLE_ADMIN,
                )
            )
        assert result.id == "team-1"

    def test_admin_role_insufficient_for_owner_required(self, regular_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(
            members=[TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_ADMIN)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    check_team_access(
                        "team-1",
                        regular_user,
                        MagicMock(),
                        required_role=TEAM_ROLE_OWNER,
                    )
                )
        assert exc_info.value.status_code == 403

    def test_owner_can_access_with_owner_required(self, regular_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(
            members=[TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_OWNER)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            result = asyncio.run(
                check_team_access(
                    "team-1",
                    regular_user,
                    MagicMock(),
                    required_role=TEAM_ROLE_OWNER,
                )
            )
        assert result.id == "team-1"

    def test_user_without_team_read_denied(self, no_perms_user):
        from app.api.v1.helpers.teams import check_team_access

        team = self._make_team(
            members=[TeamMember(user_id=str(no_perms_user.id), role=TEAM_ROLE_MEMBER)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    check_team_access(
                        "team-1",
                        no_perms_user,
                        MagicMock(),
                    )
                )
        assert exc_info.value.status_code == 403


class TestGetTeamWithAccess:
    """Tests for get_team_with_access — bypass for global team:update permission."""

    def test_user_with_team_update_gets_direct_access(self, admin_user):
        from app.api.v1.helpers.teams import get_team_with_access

        team = Team(id="team-1", name="Team", members=[])
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            result = asyncio.run(
                get_team_with_access(
                    "team-1",
                    admin_user,
                    MagicMock(),
                )
            )
        assert result.id == "team-1"

    def test_user_with_team_update_gets_404_if_not_found(self, admin_user):
        from app.api.v1.helpers.teams import get_team_with_access

        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=None)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_team_with_access(
                        "missing",
                        admin_user,
                        MagicMock(),
                    )
                )
        assert exc_info.value.status_code == 404

    def test_user_without_team_update_falls_back_to_role_check(self, regular_user):
        from app.api.v1.helpers.teams import get_team_with_access

        team = Team(
            id="team-1",
            name="Team",
            members=[TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_ADMIN)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            # Admin role satisfies default TEAM_ROLE_ADMIN requirement
            result = asyncio.run(
                get_team_with_access(
                    "team-1",
                    regular_user,
                    MagicMock(),
                )
            )
        assert result.id == "team-1"

    def test_regular_member_denied_without_admin_role(self, regular_user):
        from app.api.v1.helpers.teams import get_team_with_access

        team = Team(
            id="team-1",
            name="Team",
            members=[TeamMember(user_id=str(regular_user.id), role=TEAM_ROLE_MEMBER)],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=team)

        with patch(f"{HELPERS_TEAMS}.TeamRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_team_with_access(
                        "team-1",
                        regular_user,
                        MagicMock(),
                    )
                )
        assert exc_info.value.status_code == 403


class TestCheckWebhookPermission:
    """Tests for check_webhook_permission — project vs global authorization."""

    def _make_webhook(self, project_id="proj-1"):
        return Webhook(
            id="wh-1",
            project_id=project_id,
            url="https://example.com/hook",
            events=["scan_completed"],
        )

    def test_project_webhook_user_with_perm_and_project_access(self, regular_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission
        from app.core.permissions import Permissions

        webhook = self._make_webhook(project_id="proj-1")

        with patch(f"{HELPERS_WEBHOOKS}.check_project_access", new_callable=AsyncMock) as mock_access:
            asyncio.run(
                check_webhook_permission(
                    webhook,
                    regular_user,
                    MagicMock(),
                    Permissions.WEBHOOK_READ,
                )
            )
        # Should check project access (at viewer level, no required_role)
        mock_access.assert_called_once()
        call_args = mock_access.call_args
        assert call_args[0][0] == "proj-1"

    def test_project_webhook_user_without_perm_needs_admin(self, viewer_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission

        webhook = self._make_webhook(project_id="proj-1")

        with patch(f"{HELPERS_WEBHOOKS}.check_project_access", new_callable=AsyncMock) as mock_access:
            asyncio.run(
                check_webhook_permission(
                    webhook,
                    viewer_user,
                    MagicMock(),
                    "webhook:update",
                )
            )
        # Should require PROJECT_ROLE_ADMIN
        call_kwargs = mock_access.call_args
        assert call_kwargs.kwargs["required_role"] == "admin"

    def test_global_webhook_requires_system_manage(self, regular_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission

        webhook = self._make_webhook(project_id=None)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                check_webhook_permission(
                    webhook,
                    regular_user,
                    MagicMock(),
                    "webhook:read",
                )
            )
        assert exc_info.value.status_code == 403

    def test_global_webhook_admin_allowed(self, admin_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission

        webhook = self._make_webhook(project_id=None)

        # Should not raise
        asyncio.run(
            check_webhook_permission(
                webhook,
                admin_user,
                MagicMock(),
                "webhook:read",
            )
        )


class TestGetWebhookOr404:
    def test_returns_webhook_when_found(self):
        from app.api.v1.helpers.webhooks import get_webhook_or_404

        webhook = Webhook(
            id="wh-1",
            url="https://example.com",
            events=["scan_completed"],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=webhook)

        result = asyncio.run(get_webhook_or_404(mock_repo, "wh-1"))
        assert result.id == "wh-1"

    def test_raises_404_when_not_found(self):
        from app.api.v1.helpers.webhooks import get_webhook_or_404

        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(get_webhook_or_404(mock_repo, "missing"))
        assert exc_info.value.status_code == 404
