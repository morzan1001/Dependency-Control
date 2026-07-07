"""Tests for project API endpoints (notification settings + CSV export)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


from app.models.project import Project, ProjectMember, Scan
from app.models.user import User
from app.schemas.project import ProjectNotificationSettings

MODULE = "app.api.v1.endpoints.projects"


def _make_admin_user(user_id="admin-member-1"):
    return User(
        id=user_id,
        username="proj-admin",
        email="proj-admin@test.com",
        permissions=[],
    )


def _make_project(admin_id="admin-member-1"):
    return Project(
        id="proj-1",
        name="Demo",
        members=[ProjectMember(user_id=admin_id, role="admin")],
    )


class TestUpdateNotificationSettingsAdmin:
    """BUG-1: a project admin's own notification_preferences must be persisted."""

    def _run(self, current_user, project, settings, project_repo):
        from app.api.v1.endpoints.projects import update_notification_settings

        with patch(f"{MODULE}.check_project_access", AsyncMock(return_value=project)):
            with patch(f"{MODULE}.ProjectRepository", return_value=project_repo):
                return asyncio.run(
                    update_notification_settings(
                        project_id="proj-1",
                        settings=settings,
                        current_user=current_user,
                        db=MagicMock(),
                    )
                )

    def test_admin_preferences_are_persisted(self):
        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        settings = ProjectNotificationSettings(
            notification_preferences={"analysis_completed": ["email", "slack"]},
        )
        project_repo = MagicMock()
        project_repo.update = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        # The admin's own member preferences must be written via update_member.
        project_repo.update_member.assert_awaited_once()
        args = project_repo.update_member.await_args.args
        assert args[0] == "proj-1"
        assert args[1] == user.id
        assert args[2] == {"members.0.notification_preferences": {"analysis_completed": ["email", "slack"]}}

    def test_admin_preferences_only_no_enforcement_is_not_a_noop(self):
        """With no enforcement change, update_data is empty; prefs must still persist."""
        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        settings = ProjectNotificationSettings(
            notification_preferences={"vulnerability_found": ["slack"]},
            # enforce_notification_settings omitted -> None -> update_data empty
        )
        project_repo = MagicMock()
        project_repo.update = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        # No enforcement change => no blanket project update.
        project_repo.update.assert_not_awaited()
        # But the admin's preferences are still saved.
        project_repo.update_member.assert_awaited_once()
        assert project_repo.update_member.await_args.args[2] == {
            "members.0.notification_preferences": {"vulnerability_found": ["slack"]}
        }

    def test_admin_enforcement_and_preferences_both_persisted(self):
        user = _make_admin_user()
        project = _make_project(admin_id=user.id)
        settings = ProjectNotificationSettings(
            notification_preferences={"analysis_completed": ["email"]},
            enforce_notification_settings=True,
        )
        project_repo = MagicMock()
        project_repo.update = AsyncMock()
        project_repo.update_member = AsyncMock()
        project_repo.get_by_id = AsyncMock(return_value=project)

        self._run(user, project, settings, project_repo)

        project_repo.update.assert_awaited_once()
        assert project_repo.update.await_args.args[1] == {"enforce_notification_settings": True}
        project_repo.update_member.assert_awaited_once()


class TestExportProjectCsv:
    """EXTRA NOTE: CSV export must read the complete findings collection."""

    def test_export_reads_findings_collection_not_summary(self):
        from app.api.v1.endpoints.projects import export_project_csv

        # Scan carries a capped/vuln-only findings_summary that must be ignored.
        scan = Scan(id="scan-1", project_id="proj-1", branch="main", findings_summary=None)

        scan_repo = MagicMock()
        scan_repo.get_latest_for_project = AsyncMock(return_value=scan)

        findings = [
            {
                "finding_id": "CVE-2021-1",
                "component": "libfoo",
                "version": "1.0.0",
                "type": "vulnerability",
                "severity": "HIGH",
                "description": "boom",
                "details": {"fixed_version": "1.0.1"},
            },
            {
                # Non-vulnerability finding: would be missing from findings_summary.
                "finding_id": "SECRET-1",
                "component": "config.yaml",
                "version": "",
                "type": "secret",
                "severity": "CRITICAL",
                "description": "hardcoded key",
                "details": {},
            },
        ]

        async def _fake_iterate_raw(query, projection):
            assert query == {"scan_id": "scan-1"}
            for f in findings:
                yield f

        finding_repo = MagicMock()
        finding_repo.iterate_raw = _fake_iterate_raw

        with patch(f"{MODULE}.check_project_access", AsyncMock(return_value=_make_project())):
            with patch(f"{MODULE}.ScanRepository", return_value=scan_repo):
                with patch(f"{MODULE}.FindingRepository", return_value=finding_repo):
                    response = asyncio.run(
                        export_project_csv(
                            project_id="proj-1",
                            current_user=_make_admin_user(),
                            db=MagicMock(),
                        )
                    )

        body = response.body.decode()
        # Vulnerability id column uses finding_id; fixed_version populated.
        assert "CVE-2021-1" in body
        assert "1.0.1" in body
        # Non-vulnerability finding is included (complete export).
        assert "SECRET-1" in body
        assert "hardcoded key" in body
