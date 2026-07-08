"""Tests for email notification templates."""

from app.services.notifications.templates import (
    get_2fa_disabled_template,
    get_2fa_enabled_template,
    get_advisory_template,
    get_analysis_completed_template,
    get_announcement_template,
    get_invitation_template,
    get_password_changed_template,
    get_password_reset_template,
    get_project_member_added_template,
    get_system_invitation_template,
    get_verification_email_template,
    get_vulnerability_found_template,
)


class TestGetVerificationEmailTemplate:
    def test_renders_without_error(self):
        result = get_verification_email_template("https://example.com/verify?token=abc")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        result = get_verification_email_template("https://example.com/verify?token=abc")
        assert len(result) > 0

    def test_contains_verification_link(self):
        link = "https://example.com/verify?token=abc123"
        result = get_verification_email_template(link)
        assert link in result

    def test_contains_project_name(self):
        result = get_verification_email_template("https://example.com/verify", project_name="TestProject")
        assert "TestProject" in result

    def test_default_project_name(self):
        result = get_verification_email_template("https://example.com/verify")
        assert "Dependency Control" in result


class TestGetPasswordResetTemplate:
    def _render(self, **overrides):
        defaults = {
            "username": "testuser",
            "link": "https://example.com/reset?token=xyz",
            "project_name": "TestProject",
            "valid_hours": 2,
        }
        defaults.update(overrides)
        return get_password_reset_template(**defaults)

    def test_renders_without_error(self):
        result = self._render()
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        result = self._render()
        assert len(result) > 0

    def test_contains_reset_link(self):
        link = "https://example.com/reset?token=unique"
        result = self._render(link=link)
        assert link in result

    def test_contains_project_name(self):
        result = self._render(project_name="MyApp")
        assert "MyApp" in result


class TestGetInvitationTemplate:
    def _render(self, **overrides):
        defaults = {
            "invitation_link": "https://example.com/invite?token=abc",
            "project_name": "TestProject",
            "inviter_name": "Alice",
            "team_name": "Security Team",
        }
        defaults.update(overrides)
        return get_invitation_template(**defaults)

    def test_renders_without_error(self):
        result = self._render()
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        assert len(self._render()) > 0

    def test_contains_invitation_link(self):
        link = "https://example.com/invite?token=unique"
        result = self._render(invitation_link=link)
        assert link in result

    def test_contains_inviter_name(self):
        result = self._render(inviter_name="Bob")
        assert "Bob" in result

    def test_contains_team_name(self):
        result = self._render(team_name="DevOps")
        assert "DevOps" in result


class TestGetSystemInvitationTemplate:
    def _render(self, **overrides):
        defaults = {
            "invitation_link": "https://example.com/sys-invite?token=abc",
            "project_name": "TestProject",
            "inviter_name": "Admin",
        }
        defaults.update(overrides)
        return get_system_invitation_template(**defaults)

    def test_renders_without_error(self):
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        assert len(self._render()) > 0

    def test_contains_invitation_link(self):
        link = "https://example.com/sys-invite?token=xyz"
        result = self._render(invitation_link=link)
        assert link in result

    def test_contains_inviter_name(self):
        result = self._render(inviter_name="SysAdmin")
        assert "SysAdmin" in result


class TestGetVulnerabilityFoundTemplate:
    def _render(self, **overrides):
        defaults = {
            "report_link": "https://example.com/report/123",
            "project_name": "TestProject",
            "project_name_scanned": "my-app",
            "vulnerabilities": [{"id": "CVE-2024-001", "severity": "HIGH"}],
        }
        defaults.update(overrides)
        return get_vulnerability_found_template(**defaults)

    def test_renders_without_error(self):
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        assert len(self._render()) > 0

    def test_contains_report_link(self):
        link = "https://example.com/report/456"
        result = self._render(report_link=link)
        assert link in result

    def test_contains_scanned_project_name(self):
        result = self._render(project_name_scanned="vuln-target")
        assert "vuln-target" in result


class TestGetAnalysisCompletedTemplate:
    def _render(self, **overrides):
        defaults = {
            "analysis_link": "https://example.com/analysis/789",
            "project_name": "TestProject",
            "project_name_scanned": "my-service",
            "total_findings": 5,
        }
        defaults.update(overrides)
        return get_analysis_completed_template(**defaults)

    def test_renders_without_error(self):
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        assert len(self._render()) > 0

    def test_contains_analysis_link(self):
        link = "https://example.com/analysis/999"
        result = self._render(analysis_link=link)
        assert link in result

    def test_contains_scanned_project_name(self):
        result = self._render(project_name_scanned="backend-api")
        assert "backend-api" in result


class TestGetAdvisoryTemplate:
    def _render(self, **overrides):
        defaults = {
            "project_link": "https://example.com/project/1",
            "project_name": "TestProject",
            "project_name_scanned": "frontend-app",
            "message": "New advisory published",
            "findings": [{"title": "Advisory-001"}],
        }
        defaults.update(overrides)
        return get_advisory_template(**defaults)

    def test_renders_without_error(self):
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        assert len(self._render()) > 0

    def test_contains_project_link(self):
        link = "https://example.com/project/42"
        result = self._render(project_link=link)
        assert link in result

    def test_contains_message(self):
        result = self._render(message="Critical security update")
        assert "Critical security update" in result


class TestGetAnnouncementTemplate:
    def test_renders_without_error(self):
        result = get_announcement_template(message="System maintenance scheduled")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        result = get_announcement_template(message="Scheduled downtime")
        assert len(result) > 0

    def test_contains_message(self):
        result = get_announcement_template(message="Platform upgrade complete")
        assert "Platform upgrade complete" in result

    def test_default_project_name(self):
        result = get_announcement_template(message="test")
        assert "Dependency Control" in result


class TestGetPasswordChangedTemplate:
    def _render(self, **overrides):
        defaults = {
            "username": "testuser",
            "login_link": "https://example.com/login",
            "project_name": "TestProject",
        }
        defaults.update(overrides)
        return get_password_changed_template(**defaults)

    def test_renders_without_error(self):
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        assert len(self._render()) > 0

    def test_contains_login_link(self):
        link = "https://example.com/signin"
        result = self._render(login_link=link)
        assert link in result


class TestGet2faEnabledTemplate:
    def test_renders_without_error(self):
        result = get_2fa_enabled_template(username="alice", project_name="TestProject")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        result = get_2fa_enabled_template(username="alice", project_name="TestProject")
        assert len(result) > 0

    def test_contains_project_name(self):
        result = get_2fa_enabled_template(username="alice", project_name="SecureApp")
        assert "SecureApp" in result


class TestGet2faDisabledTemplate:
    def test_renders_without_error(self):
        result = get_2fa_disabled_template(username="bob", project_name="TestProject")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        result = get_2fa_disabled_template(username="bob", project_name="TestProject")
        assert len(result) > 0

    def test_contains_project_name(self):
        result = get_2fa_disabled_template(username="bob", project_name="SafeApp")
        assert "SafeApp" in result


class TestGetProjectMemberAddedTemplate:
    def _render(self, **overrides):
        defaults = {
            "target_project_name": "my-project",
            "inviter_name": "Charlie",
            "role": "developer",
            "link": "https://example.com/project/my-project",
        }
        defaults.update(overrides)
        return get_project_member_added_template(**defaults)

    def test_renders_without_error(self):
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        assert len(self._render()) > 0

    def test_contains_project_link(self):
        link = "https://example.com/project/other"
        result = self._render(link=link)
        assert link in result

    def test_contains_inviter_name(self):
        result = self._render(inviter_name="Diana")
        assert "Diana" in result

    def test_contains_target_project_name(self):
        result = self._render(target_project_name="super-project")
        assert "super-project" in result

    def test_contains_role(self):
        result = self._render(role="maintainer")
        assert "maintainer" in result
