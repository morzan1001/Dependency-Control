import os
from jinja2 import Environment, FileSystemLoader
from typing import Any, Dict

# Setup Jinja2 environment
current_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(current_dir, "../../templates/email")
env = Environment(loader=FileSystemLoader(template_dir))

def render_template(template_name: str, context: Dict[str, Any]) -> str:
    template = env.get_template(template_name)
    return template.render(**context)

def get_verification_email_template(verification_link: str, project_name: str = "Dependency Control") -> str:
    return render_template("verification.html", {
        "link": verification_link,
        "project_name": project_name
    })

def get_password_reset_template(reset_link: str, project_name: str, valid_hours: int = 24) -> str:
    return render_template("password_reset.html", {
        "link": reset_link,
        "project_name": project_name,
        "valid_hours": valid_hours
    })

def get_invitation_template(invitation_link: str, project_name: str, inviter_name: str, team_name: str) -> str:
    return render_template("invitation.html", {
        "link": invitation_link,
        "project_name": project_name,
        "inviter_name": inviter_name,
        "team_name": team_name
    })

def get_system_invitation_template(invitation_link: str, project_name: str, inviter_name: str) -> str:
    return render_template("system_invitation.html", {
        "link": invitation_link,
        "project_name": project_name,
        "inviter_name": inviter_name
    })

def get_vulnerability_found_template(report_link: str, project_name: str, project_name_scanned: str, vulnerabilities: list) -> str:
    return render_template("vulnerability_found.html", {
        "link": report_link,
        "project_name": project_name,
        "project_name_scanned": project_name_scanned,
        "vulnerabilities": vulnerabilities
    })

def get_analysis_completed_template(analysis_link: str, project_name: str, project_name_scanned: str, stats: Dict[str, Any]) -> str:
    return render_template("analysis_completed.html", {
        "link": analysis_link,
        "project_name": project_name,
        "project_name_scanned": project_name_scanned,
        "stats": stats
    })

def get_password_changed_template(username: str, login_link: str, project_name: str) -> str:
    return render_template("password_changed.html", {
        "username": username,
        "login_link": login_link,
        "project_name": project_name
    })

def get_2fa_enabled_template(username: str, project_name: str) -> str:
    return render_template("2fa_enabled.html", {
        "username": username,
        "project_name": project_name
    })

def get_2fa_disabled_template(username: str, project_name: str) -> str:
    return render_template("2fa_disabled.html", {
        "username": username,
        "project_name": project_name
    })
