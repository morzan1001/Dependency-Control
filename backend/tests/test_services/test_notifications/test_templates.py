"""Tests for email notification templates."""

import pytest
from jinja2 import UndefinedError

from app.core.config import settings
from app.core.constants import PASSWORD_RESET_TOKEN_EXPIRE_HOURS
from app.schemas.notification import AlertVulnerability
from app.services.notifications import templates
from app.services.notifications.templates import (
    get_2fa_disabled_template,
    get_2fa_enabled_template,
    get_advisory_template,
    get_analysis_completed_template,
    get_announcement_template,
    get_password_changed_template,
    get_password_reset_template,
    get_project_member_added_template,
    get_system_invitation_template,
    get_verification_email_template,
    get_vulnerability_found_template,
)


def _vuln(**fields):
    return AlertVulnerability(**fields).model_dump()


@pytest.fixture
def renamed(monkeypatch):
    monkeypatch.setitem(templates.env.globals, "project_name", "Acme Deps")


class TestProjectName:
    def test_every_mail_carries_the_configured_project_name(self):
        assert settings.PROJECT_NAME in get_verification_email_template("https://example.com/verify")

    @pytest.mark.parametrize(
        "render",
        [
            lambda: get_verification_email_template("https://example.com/verify"),
            lambda: get_announcement_template(message="Platform upgrade complete"),
            lambda: get_2fa_enabled_template(username="alice"),
            lambda: get_project_member_added_template(
                target_project_name="p", inviter_name="i", role="r", link="https://example.com/p"
            ),
        ],
    )
    def test_a_renamed_deployment_is_named_in_every_mail(self, renamed, render):
        assert "Acme Deps" in render()


def test_a_context_value_no_caller_passes_fails_the_render_instead_of_going_out_blank():
    with pytest.raises(UndefinedError):
        templates.render_template("password_reset.html", {"username": "u", "link": "https://example.com/reset"})


class TestGetVerificationEmailTemplate:
    def test_contains_verification_link(self):
        link = "https://example.com/verify?token=abc123"
        result = get_verification_email_template(link)
        assert link in result


class TestGetPasswordResetTemplate:
    def _render(self, **overrides):
        defaults = {"link": "https://example.com/reset?token=xyz"}
        defaults.update(overrides)
        return get_password_reset_template(**defaults)

    def test_contains_reset_link(self):
        link = "https://example.com/reset?token=unique"
        result = self._render(link=link)
        assert link in result

    def test_states_the_lifetime_the_reset_token_really_has(self):
        assert PASSWORD_RESET_TOKEN_EXPIRE_HOURS == 1
        assert "This link will expire in 1 hour." in self._render()


class TestGetSystemInvitationTemplate:
    def _render(self, **overrides):
        defaults = {
            "invitation_link": "https://example.com/sys-invite?token=abc",
            "inviter_name": "Admin",
        }
        defaults.update(overrides)
        return get_system_invitation_template(**defaults)

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
            "project_name_scanned": "my-app",
            "vulnerabilities": [_vuln(id="CVE-2024-001", severity="HIGH")],
            "priority_count": 1,
        }
        defaults.update(overrides)
        return get_vulnerability_found_template(**defaults)

    def test_contains_report_link(self):
        link = "https://example.com/report/456"
        result = self._render(report_link=link)
        assert link in result

    def test_contains_scanned_project_name(self):
        result = self._render(project_name_scanned="vuln-target")
        assert "vuln-target" in result

    @pytest.mark.parametrize(
        ("counts", "banner"),
        [
            pytest.param({"kev_count": 1}, "Known Exploited Vulnerabilities Detected", id="kev"),
            pytest.param({"high_epss_count": 1}, "High Exploitation Probability", id="high-epss"),
        ],
    )
    def test_a_banner_shows_exactly_when_its_bucket_has_a_vulnerability(self, counts, banner):
        assert banner in self._render(**counts)
        assert banner not in self._render()

    def test_the_high_epss_banner_and_badge_use_the_one_threshold(self):
        result = self._render(
            vulnerabilities=[_vuln(id="CVE-2024-001", severity="MEDIUM", epss_score=0.1)],
            high_epss_count=1,
        )
        assert "has EPSS &gt;= 10%" in result
        assert "EPSS: 10.0%" in result

    def test_a_table_shorter_than_the_alert_says_how_much_shorter(self):
        listed = 10
        found = 431

        result = self._render(
            vulnerabilities=[_vuln(id=f"CVE-2024-{index:04d}", severity="HIGH") for index in range(listed)],
            priority_count=found,
        )

        assert f"{listed} of {found} Priority (Critical/High/KEV/High EPSS)" in result

    def test_only_a_vulnerability_in_the_high_epss_bucket_carries_the_epss_badge(self):
        from app.core.constants import EPSS_HIGH_THRESHOLD

        high = self._render(vulnerabilities=[_vuln(id="CVE-1", severity="HIGH", epss_score=EPSS_HIGH_THRESHOLD)])
        below = self._render(vulnerabilities=[_vuln(id="CVE-2", severity="HIGH", epss_score=0.0999)])

        assert ("EPSS: 10.0%" in high, "EPSS:" in below) == (True, False)


class TestGetAnalysisCompletedTemplate:
    def _render(self, **overrides):
        defaults = {
            "analysis_link": "https://example.com/analysis/789",
            "project_name_scanned": "my-service",
            "total_findings": 5,
            "analyzer_count": 1,
        }
        defaults.update(overrides)
        return get_analysis_completed_template(**defaults)

    def test_contains_analysis_link(self):
        link = "https://example.com/analysis/999"
        result = self._render(analysis_link=link)
        assert link in result

    def test_contains_scanned_project_name(self):
        result = self._render(project_name_scanned="backend-api")
        assert "backend-api" in result

    @pytest.mark.parametrize(
        ("analyzer_count", "headline"),
        [pytest.param(1, "1 analyzer ran.", id="one"), pytest.param(2, "2 analyzers ran.", id="two")],
    )
    def test_the_headline_counts_the_analyzers_not_the_summary_lines(self, analyzer_count, headline):
        summary = ["trivy: Success", "grype: Success", "epss_kev: Success (4 enriched)"]

        assert headline in self._render(results_summary=summary, analyzer_count=analyzer_count)


_ADVISED_PROJECT = {"id": "p1", "name": "billing", "findings": ["log4j-core (2.14.1)"]}


class TestGetAdvisoryTemplate:
    def _render(self, **overrides):
        defaults = {"message": "Rotate **now**", "projects": [_ADVISED_PROJECT], "link": "https://dc.example.com"}
        defaults.update(overrides)
        return get_advisory_template(**defaults)

    def test_each_project_links_to_its_own_page(self):
        assert '<a href="https://dc.example.com/projects/p1">billing</a>' in self._render()

    def test_the_markdown_message_arrives_formatted(self):
        assert "Rotate <strong>now</strong>" in self._render()

    def test_the_mail_carries_the_branded_header(self):
        assert "cid:logo" in self._render()

    def test_the_heading_counts_the_projects_using_the_package(self):
        assert "Your Projects Using the Package (1)" in self._render()

    def test_a_scanned_project_name_is_escaped(self):
        result = self._render(projects=[{**_ADVISED_PROJECT, "name": _HTML_INJECTION}])

        assert _HTML_INJECTION not in result
        assert _ESCAPED_INJECTION in result


class TestGetAnnouncementTemplate:
    def test_contains_message(self):
        result = get_announcement_template(message="Platform upgrade complete")
        assert "Platform upgrade complete" in result

    def test_markdown_is_rendered_once_not_shown_as_tags(self):
        result = get_announcement_template(message="Maintenance **tonight** & tomorrow\n\n- item one")

        assert "<strong>tonight</strong> &amp; tomorrow" in result
        assert "<li>item one</li>" in result
        assert "&lt;p&gt;" not in result

    def test_a_version_range_in_a_code_span_reads_as_written(self):
        assert "<code>&gt;= 2.0, &lt; 2.17.1</code>" in get_announcement_template(message="`>= 2.0, < 2.17.1`")

    def test_a_quote_and_an_autolink_keep_their_markdown_meaning(self):
        result = get_announcement_template(message="> vendor note\n\n<https://vendor.example/advisory>")

        assert "<blockquote>" in result
        assert 'href="https://vendor.example/advisory"' in result


class TestGetPasswordChangedTemplate:
    def _render(self, **overrides):
        defaults = {
            "username": "testuser",
            "login_link": "https://example.com/login",
        }
        defaults.update(overrides)
        return get_password_changed_template(**defaults)

    def test_contains_login_link(self):
        link = "https://example.com/signin"
        result = self._render(login_link=link)
        assert link in result


class TestGet2faDisabledTemplate:
    def test_contains_username(self):
        assert "bob" in get_2fa_disabled_template(username="bob")


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


_HTML_INJECTION = '<script>alert("xss")</script>'
_ESCAPED_INJECTION = "&lt;script&gt;"


class TestTemplateEscaping:
    """Every interpolated value here is chosen by a user or read off a scanned repository."""

    def test_an_inviters_display_name_is_escaped_into_the_invitation(self):
        result = get_system_invitation_template(
            invitation_link="https://example.com/invite?token=abc", inviter_name=_HTML_INJECTION
        )

        assert _HTML_INJECTION not in result
        assert _ESCAPED_INJECTION in result

    def test_a_scanned_repository_name_is_escaped_into_the_vulnerability_alert(self):
        result = get_vulnerability_found_template(
            report_link="https://example.com/report/123",
            project_name_scanned=_HTML_INJECTION,
            vulnerabilities=[_vuln(id="CVE-2024-001", severity="HIGH")],
            priority_count=1,
        )

        assert _HTML_INJECTION not in result
        assert _ESCAPED_INJECTION in result

    def test_a_finding_identifier_is_escaped_into_the_vulnerability_table(self):
        result = get_vulnerability_found_template(
            report_link="https://example.com/report/123",
            project_name_scanned="my-app",
            vulnerabilities=[_vuln(id=_HTML_INJECTION, severity="HIGH")],
            priority_count=1,
        )

        assert _HTML_INJECTION not in result
        assert _ESCAPED_INJECTION in result

    def test_raw_html_in_an_announcement_is_dropped(self):
        result = get_announcement_template(message=f"before {_HTML_INJECTION} after")

        assert "<script" not in result
        assert "xss" not in result

    @pytest.mark.parametrize("href", ["javascript:alert(1)", "data:text/html,x"])
    def test_a_link_outside_http_https_mailto_loses_its_target(self, href):
        result = get_announcement_template(message=f"[click]({href})")

        assert href not in result
        assert ">click</a>" in result
