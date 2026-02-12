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
    """Tests for verification email template rendering."""

    def test_renders_without_error(self):
        """Template should render successfully."""
        result = get_verification_email_template("https://example.com/verify?token=abc")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        result = get_verification_email_template("https://example.com/verify?token=abc")
        assert len(result) > 0

    def test_contains_verification_link(self):
        """Rendered template should contain the verification link."""
        link = "https://example.com/verify?token=abc123"
        result = get_verification_email_template(link)
        assert link in result

    def test_contains_project_name(self):
        """Rendered template should contain the project name."""
        result = get_verification_email_template("https://example.com/verify", project_name="TestProject")
        assert "TestProject" in result

    def test_default_project_name(self):
        """Rendered template should use default project name."""
        result = get_verification_email_template("https://example.com/verify")
        assert "Dependency Control" in result


class TestGetPasswordResetTemplate:
    """Tests for password reset email template rendering."""

    def _render(self, **overrides):
        """Build default password reset template context."""
        defaults = {
            "username": "testuser",
            "link": "https://example.com/reset?token=xyz",
            "project_name": "TestProject",
            "valid_hours": 2,
        }
        defaults.update(overrides)
        return get_password_reset_template(**defaults)

    def test_renders_without_error(self):
        """Template should render successfully."""
        result = self._render()
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        result = self._render()
        assert len(result) > 0

    def test_contains_reset_link(self):
        """Rendered template should contain the reset link."""
        link = "https://example.com/reset?token=unique"
        result = self._render(link=link)
        assert link in result

    def test_contains_project_name(self):
        """Rendered template should contain the project name."""
        result = self._render(project_name="MyApp")
        assert "MyApp" in result


class TestGetInvitationTemplate:
    """Tests for team invitation email template rendering."""

    def _render(self, **overrides):
        """Build default invitation template context."""
        defaults = {
            "invitation_link": "https://example.com/invite?token=abc",
            "project_name": "TestProject",
            "inviter_name": "Alice",
            "team_name": "Security Team",
        }
        defaults.update(overrides)
        return get_invitation_template(**defaults)

    def test_renders_without_error(self):
        """Template should render successfully."""
        result = self._render()
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        assert len(self._render()) > 0

    def test_contains_invitation_link(self):
        """Rendered template should contain the invitation link."""
        link = "https://example.com/invite?token=unique"
        result = self._render(invitation_link=link)
        assert link in result

    def test_contains_inviter_name(self):
        """Rendered template should contain the inviter name."""
        result = self._render(inviter_name="Bob")
        assert "Bob" in result

    def test_contains_team_name(self):
        """Rendered template should contain the team name."""
        result = self._render(team_name="DevOps")
        assert "DevOps" in result


class TestGetSystemInvitationTemplate:
    """Tests for system invitation email template rendering."""

    def _render(self, **overrides):
        """Build default system invitation template context."""
        defaults = {
            "invitation_link": "https://example.com/sys-invite?token=abc",
            "project_name": "TestProject",
            "inviter_name": "Admin",
        }
        defaults.update(overrides)
        return get_system_invitation_template(**defaults)

    def test_renders_without_error(self):
        """Template should render successfully."""
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        assert len(self._render()) > 0

    def test_contains_invitation_link(self):
        """Rendered template should contain the invitation link."""
        link = "https://example.com/sys-invite?token=xyz"
        result = self._render(invitation_link=link)
        assert link in result

    def test_contains_inviter_name(self):
        """Rendered template should contain the inviter name."""
        result = self._render(inviter_name="SysAdmin")
        assert "SysAdmin" in result


class TestGetVulnerabilityFoundTemplate:
    """Tests for vulnerability found email template rendering."""

    def _render(self, **overrides):
        """Build default vulnerability found template context."""
        defaults = {
            "report_link": "https://example.com/report/123",
            "project_name": "TestProject",
            "project_name_scanned": "my-app",
            "vulnerabilities": [{"id": "CVE-2024-001", "severity": "HIGH"}],
        }
        defaults.update(overrides)
        return get_vulnerability_found_template(**defaults)

    def test_renders_without_error(self):
        """Template should render successfully."""
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        assert len(self._render()) > 0

    def test_contains_report_link(self):
        """Rendered template should contain the report link."""
        link = "https://example.com/report/456"
        result = self._render(report_link=link)
        assert link in result

    def test_contains_scanned_project_name(self):
        """Rendered template should contain the scanned project name."""
        result = self._render(project_name_scanned="vuln-target")
        assert "vuln-target" in result


class TestGetAnalysisCompletedTemplate:
    """Tests for analysis completed email template rendering."""

    def _render(self, **overrides):
        """Build default analysis completed template context."""
        defaults = {
            "analysis_link": "https://example.com/analysis/789",
            "project_name": "TestProject",
            "project_name_scanned": "my-service",
            "total_findings": 5,
        }
        defaults.update(overrides)
        return get_analysis_completed_template(**defaults)

    def test_renders_without_error(self):
        """Template should render successfully."""
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        assert len(self._render()) > 0

    def test_contains_analysis_link(self):
        """Rendered template should contain the analysis link."""
        link = "https://example.com/analysis/999"
        result = self._render(analysis_link=link)
        assert link in result

    def test_contains_scanned_project_name(self):
        """Rendered template should contain the scanned project name."""
        result = self._render(project_name_scanned="backend-api")
        assert "backend-api" in result


class TestGetAdvisoryTemplate:
    """Tests for advisory email template rendering."""

    def _render(self, **overrides):
        """Build default advisory template context."""
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
        """Template should render successfully."""
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        assert len(self._render()) > 0

    def test_contains_project_link(self):
        """Rendered template should contain the project link."""
        link = "https://example.com/project/42"
        result = self._render(project_link=link)
        assert link in result

    def test_contains_message(self):
        """Rendered template should contain the advisory message."""
        result = self._render(message="Critical security update")
        assert "Critical security update" in result


class TestGetAnnouncementTemplate:
    """Tests for announcement email template rendering."""

    def test_renders_without_error(self):
        """Template should render successfully."""
        result = get_announcement_template(message="System maintenance scheduled")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        result = get_announcement_template(message="Scheduled downtime")
        assert len(result) > 0

    def test_contains_message(self):
        """Rendered template should contain the announcement message."""
        result = get_announcement_template(message="Platform upgrade complete")
        assert "Platform upgrade complete" in result

    def test_default_project_name(self):
        """Rendered template should use default project name."""
        result = get_announcement_template(message="test")
        assert "Dependency Control" in result


class TestGetPasswordChangedTemplate:
    """Tests for password changed email template rendering."""

    def _render(self, **overrides):
        """Build default password changed template context."""
        defaults = {
            "username": "testuser",
            "login_link": "https://example.com/login",
            "project_name": "TestProject",
        }
        defaults.update(overrides)
        return get_password_changed_template(**defaults)

    def test_renders_without_error(self):
        """Template should render successfully."""
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        assert len(self._render()) > 0

    def test_contains_login_link(self):
        """Rendered template should contain the login link."""
        link = "https://example.com/signin"
        result = self._render(login_link=link)
        assert link in result


class TestGet2faEnabledTemplate:
    """Tests for 2FA enabled email template rendering."""

    def test_renders_without_error(self):
        """Template should render successfully."""
        result = get_2fa_enabled_template(username="alice", project_name="TestProject")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        result = get_2fa_enabled_template(username="alice", project_name="TestProject")
        assert len(result) > 0

    def test_contains_project_name(self):
        """Rendered template should contain the project name."""
        result = get_2fa_enabled_template(username="alice", project_name="SecureApp")
        assert "SecureApp" in result


class TestGet2faDisabledTemplate:
    """Tests for 2FA disabled email template rendering."""

    def test_renders_without_error(self):
        """Template should render successfully."""
        result = get_2fa_disabled_template(username="bob", project_name="TestProject")
        assert isinstance(result, str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        result = get_2fa_disabled_template(username="bob", project_name="TestProject")
        assert len(result) > 0

    def test_contains_project_name(self):
        """Rendered template should contain the project name."""
        result = get_2fa_disabled_template(username="bob", project_name="SafeApp")
        assert "SafeApp" in result


class TestGetProjectMemberAddedTemplate:
    """Tests for project member added email template rendering."""

    def _render(self, **overrides):
        """Build default project member added template context."""
        defaults = {
            "target_project_name": "my-project",
            "inviter_name": "Charlie",
            "role": "developer",
            "link": "https://example.com/project/my-project",
        }
        defaults.update(overrides)
        return get_project_member_added_template(**defaults)

    def test_renders_without_error(self):
        """Template should render successfully."""
        assert isinstance(self._render(), str)

    def test_returns_non_empty(self):
        """Template should return non-empty HTML."""
        assert len(self._render()) > 0

    def test_contains_project_link(self):
        """Rendered template should contain the project link."""
        link = "https://example.com/project/other"
        result = self._render(link=link)
        assert link in result

    def test_contains_inviter_name(self):
        """Rendered template should contain the inviter name."""
        result = self._render(inviter_name="Diana")
        assert "Diana" in result

    def test_contains_target_project_name(self):
        """Rendered template should contain the target project name."""
        result = self._render(target_project_name="super-project")
        assert "super-project" in result

    def test_contains_role(self):
        """Rendered template should contain the assigned role."""
        result = self._render(role="maintainer")
        assert "maintainer" in result
