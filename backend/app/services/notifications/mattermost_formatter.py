"""Mattermost message attachment formatting."""

import re
from typing import Any

from app.core.epss import HIGH_EPSS_LABEL
from app.schemas.notification import PRIORITY_VULNS_LABEL, AlertVulnerability, scan_alert_level
from app.services.notifications.slack_formatter import (
    AFFECTED_PROJECTS_SHOWN,
    SEVERITY_EMOJI,
    format_vuln_line,
    project_findings_summary,
)

_COLOR_SUCCESS = "#36a64f"
_COLOR_DANGER = "#dc3545"
_COLOR_WARNING = "#ffc107"
_COLOR_INFO = "#2196f3"
_ALERT_COLOR = {"critical": _COLOR_DANGER, "warning": _COLOR_WARNING, "ok": _COLOR_SUCCESS}

_MARKDOWN_CONTROL = re.compile(r"([\\`*_\[\]()!>])")


def _escape_markdown(text: str) -> str:
    """Mattermost renders [label](url), ![](url) and emphasis from any text that reaches it."""
    return _MARKDOWN_CONTROL.sub(r"\\\1", text)


def build_generic_props(subject: str, message: str) -> dict[str, Any]:
    """Default Mattermost props: a simple attachment from subject + message."""
    return {
        "attachments": [
            {
                "color": _COLOR_INFO,
                "title": subject,
                "text": _escape_markdown(message),
            }
        ]
    }


def build_analysis_completed_props(
    project_name: str,
    scan_id: str,
    total_findings: int,
    severity_counts: dict[str, int],
    results_summary: list[str],
    analyzer_count: int,
    scan_link: str,
) -> dict[str, Any]:
    """Build Mattermost attachment props for analysis completed notification."""
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    fields = [
        {"short": True, "title": f"{SEVERITY_EMOJI['CRITICAL']} Critical", "value": str(critical)},
        {"short": True, "title": f"{SEVERITY_EMOJI['HIGH']} High", "value": str(high)},
        {
            "short": True,
            "title": f"{SEVERITY_EMOJI['MEDIUM']} Medium",
            "value": str(severity_counts.get("MEDIUM", 0)),
        },
        {
            "short": True,
            "title": f"{SEVERITY_EMOJI['LOW']} Low",
            "value": str(severity_counts.get("LOW", 0)),
        },
        {"short": True, "title": "Total", "value": str(total_findings)},
    ]

    text = f"Scan `{scan_id[:12]}` completed for **{_escape_markdown(project_name)}**."

    if results_summary:
        analyzer_lines = "\n".join(f"- {_escape_markdown(r)}" for r in results_summary)
        text += f"\n\n**Analyzers ({analyzer_count})**\n{analyzer_lines}"

    text += f"\n\n[View Report \u2192]({scan_link})"

    return {
        "attachments": [
            {
                "color": _ALERT_COLOR[scan_alert_level(critical, high)],
                "title": f"\U0001f4ca Analysis Completed: {project_name}",
                "title_link": scan_link,
                "text": text,
                "fields": fields,
            }
        ]
    }


def build_vulnerability_found_props(
    project_name: str,
    kev_count: int,
    high_epss_count: int,
    priority_count: int,
    critical_count: int,
    top_vulns: list[AlertVulnerability],
    scan_link: str,
) -> dict[str, Any]:
    """Build Mattermost attachment props for vulnerability found notification."""
    fields: list[dict[str, Any]] = []
    if kev_count:
        fields.append({"short": True, "title": "\u26a0\ufe0f KEV Vulnerabilities", "value": str(kev_count)})
    if high_epss_count:
        fields.append(
            {"short": True, "title": f"\U0001f4c8 High EPSS ({HIGH_EPSS_LABEL})", "value": str(high_epss_count)}
        )
    fields.append(
        {"short": True, "title": f"{SEVERITY_EMOJI['CRITICAL']} {PRIORITY_VULNS_LABEL}", "value": str(priority_count)}
    )

    lead = "critical" if critical_count else "high-priority"
    text = f"Security scan detected {lead} vulnerabilities in **{_escape_markdown(project_name)}**."

    if top_vulns:
        vuln_lines = [format_vuln_line(i, v, "*", _escape_markdown) for i, v in enumerate(top_vulns, 1)]
        text += f"\n\n**Top Priority Vulnerabilities ({len(top_vulns)} of {priority_count})**\n"
        text += "\n".join(vuln_lines)

    text += f"\n\n[View Full Report \u2192]({scan_link})"

    return {
        "attachments": [
            {
                "color": _COLOR_DANGER,
                "title": f"\U0001f6a8 Security Alert: {project_name}",
                "title_link": scan_link,
                "text": text,
                "fields": fields,
            }
        ]
    }


def build_advisory_props(
    subject: str,
    message: str,
    affected_projects: list[dict[str, Any]] | None = None,
    dashboard_link: str | None = None,
) -> dict[str, Any]:
    """Build Mattermost attachment props for advisory / broadcast notifications."""
    text = message

    if affected_projects:
        shown = affected_projects[:AFFECTED_PROJECTS_SHOWN]
        project_lines = [
            f"- **{_escape_markdown(p['name'])}**: {_escape_markdown(project_findings_summary(p['findings']))}"
            for p in shown
        ]

        text += f"\n\n**Your Projects Using the Package ({len(shown)} of {len(affected_projects)})**\n"
        text += "\n".join(project_lines)

    if dashboard_link:
        text += f"\n\n[View Dashboard \u2192]({dashboard_link})"

    return {
        "attachments": [
            {
                "color": _COLOR_WARNING,
                "title": f"\U0001f4e2 {subject}",
                "title_link": dashboard_link or "",
                "text": text,
            }
        ]
    }
