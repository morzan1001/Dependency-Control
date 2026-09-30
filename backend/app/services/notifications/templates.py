import os
from typing import Any

from jinja2 import Environment, FileSystemLoader

from app.core.config import settings
from app.core.constants import EPSS_HIGH_THRESHOLD, PASSWORD_RESET_TOKEN_EXPIRE_HOURS
from app.core.epss import HIGH_EPSS_LABEL
from app.schemas.notification import PRIORITY_VULNS_LABEL

current_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(current_dir, "../../templates/email")
env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
env.globals["project_name"] = settings.PROJECT_NAME


def render_template(template_name: str, context: dict[str, Any]) -> str:
    template = env.get_template(template_name)
    return template.render(**context)


def get_verification_email_template(verification_link: str) -> str:
    return render_template("verification.html", {"link": verification_link})


def get_email_change_template(confirmation_link: str) -> str:
    return render_template("email_change.html", {"link": confirmation_link})


def get_password_reset_template(username: str, link: str) -> str:
    return render_template(
        "password_reset.html",
        {"username": username, "link": link, "valid_hours": PASSWORD_RESET_TOKEN_EXPIRE_HOURS},
    )


def get_system_invitation_template(invitation_link: str, inviter_name: str) -> str:
    return render_template("system_invitation.html", {"link": invitation_link, "inviter_name": inviter_name})


def get_vulnerability_found_template(
    report_link: str,
    project_name_scanned: str,
    vulnerabilities: list,
    priority_count: int,
    has_kev: bool = False,
    kev_count: int = 0,
    kev_vulnerabilities: list | None = None,
    has_high_epss: bool = False,
    high_epss_count: int = 0,
) -> str:
    return render_template(
        "vulnerability_found.html",
        {
            "link": report_link,
            "project_name_scanned": project_name_scanned,
            "vulnerabilities": vulnerabilities,
            "priority_count": priority_count,
            "priority_label": PRIORITY_VULNS_LABEL,
            "high_epss_label": HIGH_EPSS_LABEL,
            "high_epss_threshold": EPSS_HIGH_THRESHOLD,
            "has_kev": has_kev,
            "kev_count": kev_count,
            "kev_vulnerabilities": kev_vulnerabilities or [],
            "has_high_epss": has_high_epss,
            "high_epss_count": high_epss_count,
        },
    )


def get_analysis_completed_template(
    analysis_link: str,
    project_name_scanned: str,
    total_findings: int,
    severity_critical: int = 0,
    severity_high: int = 0,
    severity_medium: int = 0,
    severity_low: int = 0,
    analyzer_count: int = 0,
    results_summary: list | None = None,
) -> str:
    return render_template(
        "analysis_completed.html",
        {
            "link": analysis_link,
            "project_name_scanned": project_name_scanned,
            "total_findings": total_findings,
            "severity_critical": severity_critical,
            "severity_high": severity_high,
            "severity_medium": severity_medium,
            "severity_low": severity_low,
            "analyzer_count": analyzer_count,
            "results_summary": results_summary or [],
        },
    )


def get_advisory_template(
    project_link: str,
    project_name_scanned: str,
    message: str,
    findings: list,
) -> str:
    return render_template(
        "advisory.html",
        {
            "link": project_link,
            "project_name_scanned": project_name_scanned,
            "message": message,
            "findings": findings,
        },
    )


def get_announcement_template(message: str, link: str = "#") -> str:
    return render_template("announcement.html", {"message": message, "link": link})


def get_password_changed_template(username: str, login_link: str) -> str:
    return render_template("password_changed.html", {"username": username, "login_link": login_link})


def get_2fa_enabled_template(username: str) -> str:
    return render_template("2fa_enabled.html", {"username": username})


def get_2fa_disabled_template(username: str) -> str:
    return render_template("2fa_disabled.html", {"username": username})


def get_project_member_added_template(target_project_name: str, inviter_name: str, role: str, link: str) -> str:
    return render_template(
        "project_member_added.html",
        {
            "target_project_name": target_project_name,
            "inviter_name": inviter_name,
            "role": role,
            "link": link,
        },
    )
