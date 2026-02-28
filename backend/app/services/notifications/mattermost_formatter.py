"""
Mattermost message attachment formatting.

Builds rich messages using Mattermost's message attachments feature.
Attachments support color sidebars, structured fields, and markdown text.
See: https://developers.mattermost.com/integrate/webhooks/incoming/#parameters
"""

from typing import Any, Dict, List, Optional

# Colour palette
_COLOR_SUCCESS = "#36a64f"
_COLOR_DANGER = "#dc3545"
_COLOR_WARNING = "#ffc107"
_COLOR_INFO = "#2196f3"

_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535",
}


def build_generic_props(subject: str, message: str) -> Dict[str, Any]:
    """
    Build Mattermost props with a simple attachment from any subject + message.

    Used as the default formatter when no specific props are provided.
    """
    return {
        "attachments": [
            {
                "color": _COLOR_INFO,
                "title": subject,
                "text": message,
            }
        ]
    }


def build_analysis_completed_props(
    project_name: str,
    scan_id: str,
    total_findings: int,
    severity_counts: Dict[str, int],
    results_summary: List[str],
    scan_link: str,
) -> Dict[str, Any]:
    """Build Mattermost attachment props for analysis completed notification."""
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    color = _COLOR_DANGER if critical > 0 else (_COLOR_WARNING if high > 0 else _COLOR_SUCCESS)

    fields = [
        {"short": True, "title": f"{_SEVERITY_EMOJI['CRITICAL']} Critical", "value": str(critical)},
        {"short": True, "title": f"{_SEVERITY_EMOJI['HIGH']} High", "value": str(high)},
        {
            "short": True,
            "title": f"{_SEVERITY_EMOJI['MEDIUM']} Medium",
            "value": str(severity_counts.get("MEDIUM", 0)),
        },
        {
            "short": True,
            "title": f"{_SEVERITY_EMOJI['LOW']} Low",
            "value": str(severity_counts.get("LOW", 0)),
        },
        {"short": True, "title": "Total", "value": str(total_findings)},
    ]

    text = f"Scan `{scan_id[:12]}` completed for **{project_name}**."

    if results_summary:
        analyzer_lines = "\n".join(f"- {r}" for r in results_summary)
        text += f"\n\n**Analyzers ({len(results_summary)})**\n{analyzer_lines}"

    text += f"\n\n[View Report \u2192]({scan_link})"

    return {
        "attachments": [
            {
                "color": color,
                "title": f"\U0001f4ca Analysis Completed: {project_name}",
                "title_link": scan_link,
                "text": text,
                "fields": fields,
            }
        ]
    }


def _format_vuln_line(index: int, vuln: Dict[str, Any]) -> str:
    """Format a single vulnerability line for Mattermost markdown."""
    emoji = _SEVERITY_EMOJI.get(vuln.get("severity", ""), "\u26aa")
    line = f"{index}. `{vuln['id']}` {emoji} {vuln['severity']} \u2014 {vuln['package']}"
    if vuln.get("version"):
        line += f"@{vuln['version']}"

    tags = []
    if vuln.get("in_kev"):
        tags.append("KEV")
    if vuln.get("epss_score"):
        tags.append(f"EPSS: {vuln['epss_score'] * 100:.1f}%")
    if tags:
        line += f"  *[{', '.join(tags)}]*"

    return line


def build_vulnerability_found_props(
    project_name: str,
    kev_count: int,
    high_epss_count: int,
    critical_count: int,
    top_vulns: List[Dict[str, Any]],
    scan_link: str,
) -> Dict[str, Any]:
    """Build Mattermost attachment props for vulnerability found notification."""
    fields: List[Dict[str, Any]] = []
    if kev_count:
        fields.append({"short": True, "title": "\u26a0\ufe0f KEV Vulnerabilities", "value": str(kev_count)})
    if high_epss_count:
        fields.append({"short": True, "title": "\U0001f4c8 High EPSS (>10%)", "value": str(high_epss_count)})
    fields.append(
        {"short": True, "title": f"{_SEVERITY_EMOJI['CRITICAL']} Critical/High", "value": str(critical_count)}
    )

    text = f"Security scan detected critical vulnerabilities in **{project_name}**."

    if top_vulns:
        vuln_lines = [_format_vuln_line(i, v) for i, v in enumerate(top_vulns[:10], 1)]
        text += "\n\n**Top Priority Vulnerabilities**\n" + "\n".join(vuln_lines)

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
    affected_projects: Optional[List[Dict[str, Any]]] = None,
    dashboard_link: Optional[str] = None,
) -> Dict[str, Any]:
    """Build Mattermost attachment props for advisory / broadcast notifications."""
    text = message

    if affected_projects:
        project_lines = []
        for p in affected_projects[:15]:
            findings_str = ", ".join(p.get("findings", [])[:5])
            if len(p.get("findings", [])) > 5:
                findings_str += f", +{len(p['findings']) - 5} more"
            project_lines.append(f"- **{p['name']}**: {findings_str}")

        text += f"\n\n**Affected Projects ({len(affected_projects)})**\n" + "\n".join(project_lines)

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
