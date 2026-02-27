"""
Slack Block Kit message formatting.

Builds rich, visually appealing Slack messages using Block Kit.
See: https://api.slack.com/block-kit
"""

from typing import Any, Dict, List, Optional

# Slack Block Kit limits
_HEADER_MAX_LENGTH = 150
_SECTION_TEXT_MAX_LENGTH = 3000
_MAX_BLOCKS = 50
_MAX_FIELDS = 10

_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",  # red circle
    "HIGH": "\U0001f7e0",  # orange circle
    "MEDIUM": "\U0001f7e1",  # yellow circle
    "LOW": "\U0001f535",  # blue circle
}


def build_generic_blocks(subject: str, message: str) -> List[Dict[str, Any]]:
    """
    Build a clean Block Kit layout from any subject + message.

    Used as the default formatter when no specific blocks are provided.
    """
    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": subject[:_HEADER_MAX_LENGTH],
                "emoji": True,
            },
        },
        {"type": "divider"},
    ]

    remaining = message.strip()
    while remaining and len(blocks) < _MAX_BLOCKS - 1:
        chunk = remaining[:_SECTION_TEXT_MAX_LENGTH]
        remaining = remaining[_SECTION_TEXT_MAX_LENGTH:]
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": chunk},
            }
        )

    return blocks


def build_analysis_completed_blocks(
    project_name: str,
    scan_id: str,
    total_findings: int,
    severity_counts: Dict[str, int],
    results_summary: List[str],
    scan_link: str,
) -> List[Dict[str, Any]]:
    """Build rich Block Kit layout for analysis completed notification."""
    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"\U0001f4ca Analysis Completed: {project_name}"[:_HEADER_MAX_LENGTH],
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Scan `{scan_id[:12]}` completed for *{project_name}*.",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Findings Summary*"},
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"{_SEVERITY_EMOJI['CRITICAL']} *Critical:* {severity_counts.get('CRITICAL', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"{_SEVERITY_EMOJI['HIGH']} *High:* {severity_counts.get('HIGH', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"{_SEVERITY_EMOJI['MEDIUM']} *Medium:* {severity_counts.get('MEDIUM', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"{_SEVERITY_EMOJI['LOW']} *Low:* {severity_counts.get('LOW', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total:* {total_findings}",
                },
            ],
        },
    ]

    if results_summary:
        results_text = "\n".join(f"\u2022 {r}" for r in results_summary)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Analyzers ({len(results_summary)})*\n{results_text}"[
                        :_SECTION_TEXT_MAX_LENGTH
                    ],
                },
            }
        )

    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Report", "emoji": True},
                    "url": scan_link,
                    "style": "primary",
                }
            ],
        }
    )

    return blocks


def _format_vuln_line(index: int, vuln: Dict[str, Any]) -> str:
    """Format a single vulnerability line for Block Kit."""
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
        line += f"  _[{', '.join(tags)}]_"

    return line


def build_vulnerability_found_blocks(
    project_name: str,
    kev_count: int,
    high_epss_count: int,
    critical_count: int,
    top_vulns: List[Dict[str, Any]],
    scan_link: str,
) -> List[Dict[str, Any]]:
    """Build rich Block Kit layout for vulnerability found notification."""
    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"\U0001f6a8 Security Alert: {project_name}"[:_HEADER_MAX_LENGTH],
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Security scan detected critical vulnerabilities in *{project_name}*.",
            },
        },
        {"type": "divider"},
    ]

    # Stats fields
    fields: List[Dict[str, str]] = []
    if kev_count:
        fields.append({"type": "mrkdwn", "text": f"\u26a0\ufe0f *KEV Vulnerabilities:* {kev_count}"})
    if high_epss_count:
        fields.append({"type": "mrkdwn", "text": f"\U0001f4c8 *High EPSS (>10%):* {high_epss_count}"})
    fields.append(
        {"type": "mrkdwn", "text": f"{_SEVERITY_EMOJI['CRITICAL']} *Critical/High:* {critical_count}"}
    )

    blocks.append({"type": "section", "fields": fields[:_MAX_FIELDS]})

    # Top vulnerabilities
    if top_vulns:
        vuln_lines = [_format_vuln_line(i, v) for i, v in enumerate(top_vulns[:10], 1)]
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ("*Top Priority Vulnerabilities*\n" + "\n".join(vuln_lines))[
                        :_SECTION_TEXT_MAX_LENGTH
                    ],
                },
            }
        )

    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Full Report", "emoji": True},
                    "url": scan_link,
                    "style": "danger",
                }
            ],
        }
    )

    return blocks


def build_advisory_blocks(
    subject: str,
    message: str,
    affected_projects: Optional[List[Dict[str, Any]]] = None,
    dashboard_link: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build Block Kit layout for advisory / broadcast notifications."""
    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"\U0001f4e2 {subject}"[:_HEADER_MAX_LENGTH],
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": message[:_SECTION_TEXT_MAX_LENGTH]},
        },
    ]

    if affected_projects:
        project_lines = []
        for p in affected_projects[:15]:
            findings_str = ", ".join(p.get("findings", [])[:5])
            if len(p.get("findings", [])) > 5:
                findings_str += f", +{len(p['findings']) - 5} more"
            project_lines.append(f"\u2022 *{p['name']}*: {findings_str}")

        text = f"*Affected Projects ({len(affected_projects)})*\n" + "\n".join(project_lines)
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text[:_SECTION_TEXT_MAX_LENGTH]},
            }
        )

    if dashboard_link:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Dashboard", "emoji": True},
                        "url": dashboard_link,
                    }
                ],
            }
        )

    return blocks
