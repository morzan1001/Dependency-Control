"""Slack Block Kit message formatting."""

from collections.abc import Callable
from typing import Any

from app.core.epss import HIGH_EPSS_LABEL
from app.schemas.notification import PRIORITY_VULNS_LABEL, AlertVulnerability

# Slack Block Kit limits: a payload past any of these is rejected outright.
_HEADER_MAX_LENGTH = 150
_SECTION_TEXT_MAX_LENGTH = 3000
_MAX_BLOCKS = 50

_CUT_MARKER = "… [cut]"
AFFECTED_PROJECTS_SHOWN = 15
PROJECT_FINDINGS_SHOWN = 5


def _escape_mrkdwn(text: str) -> str:
    """Slack reads a bare &, < or > as the start of a link, mention or entity."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _fit(text: str) -> str:
    """Section text within Slack's per-block budget, saying so when it did not fit."""
    if len(text) <= _SECTION_TEXT_MAX_LENGTH:
        return text
    return text[: _SECTION_TEXT_MAX_LENGTH - len(_CUT_MARKER)] + _CUT_MARKER


SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",  # red circle
    "HIGH": "\U0001f7e0",  # orange circle
    "MEDIUM": "\U0001f7e1",  # yellow circle
    "LOW": "\U0001f535",  # blue circle
}


# Escapes show literally inside a code span, so these are dropped from the id instead.
_CODE_SPAN_UNSAFE = str.maketrans("", "", "`<>&")


def format_vuln_line(index: int, vuln: AlertVulnerability, emphasis: str, escape: Callable[[str], str]) -> str:
    """One alert line, with ``escape`` applied to the SBOM-sourced package and version."""
    emoji = SEVERITY_EMOJI.get(vuln.severity, "\u26aa")
    line = f"{index}. `{vuln.id.translate(_CODE_SPAN_UNSAFE)}` {emoji} {vuln.severity} \u2014 "
    line += escape(vuln.versioned_package)
    if vuln.tags:
        line += f"  {emphasis}[{', '.join(vuln.tags)}]{emphasis}"
    return line


def project_findings_summary(findings: list[str]) -> str:
    hidden = len(findings) - PROJECT_FINDINGS_SHOWN
    shown = ", ".join(findings[:PROJECT_FINDINGS_SHOWN])
    return f"{shown}, +{hidden} more" if hidden > 0 else shown


def _section_blocks(text: str, slots: int) -> list[dict[str, Any]]:
    """``text`` in at most ``slots`` sections, the last one saying how much did not fit."""
    remaining = text.strip()
    chunks: list[str] = []
    while remaining and len(chunks) < slots - 1:
        chunks.append(remaining[:_SECTION_TEXT_MAX_LENGTH])
        remaining = remaining[_SECTION_TEXT_MAX_LENGTH:]
    if remaining:
        chunks.append(f"_{len(remaining)} more characters did not fit in this message._")
    return [{"type": "section", "text": {"type": "mrkdwn", "text": chunk}} for chunk in chunks]


def build_generic_blocks(subject: str, message: str) -> list[dict[str, Any]]:
    """Default Block Kit layout built from subject + message."""
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": subject[:_HEADER_MAX_LENGTH],
                "emoji": True,
            },
        },
        {"type": "divider"},
        *_section_blocks(_escape_mrkdwn(message), _MAX_BLOCKS - 2),
    ]


def build_analysis_completed_blocks(
    project_name: str,
    scan_id: str,
    total_findings: int,
    severity_counts: dict[str, int],
    results_summary: list[str],
    analyzer_count: int,
    scan_link: str,
) -> list[dict[str, Any]]:
    """Build rich Block Kit layout for analysis completed notification."""
    blocks: list[dict[str, Any]] = [
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
                "text": f"Scan `{scan_id[:12]}` completed for *{_escape_mrkdwn(project_name)}*.",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Findings Summary*"},
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"{SEVERITY_EMOJI['CRITICAL']} *Critical:* {severity_counts.get('CRITICAL', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"{SEVERITY_EMOJI['HIGH']} *High:* {severity_counts.get('HIGH', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"{SEVERITY_EMOJI['MEDIUM']} *Medium:* {severity_counts.get('MEDIUM', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"{SEVERITY_EMOJI['LOW']} *Low:* {severity_counts.get('LOW', 0)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total:* {total_findings}",
                },
            ],
        },
    ]

    if results_summary:
        results_text = "\n".join(f"\u2022 {_escape_mrkdwn(r)}" for r in results_summary)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": _fit(f"*Analyzers ({analyzer_count})*\n{results_text}"),
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


def build_vulnerability_found_blocks(
    project_name: str,
    kev_count: int,
    high_epss_count: int,
    priority_count: int,
    critical_count: int,
    top_vulns: list[AlertVulnerability],
    scan_link: str,
) -> list[dict[str, Any]]:
    """Build rich Block Kit layout for vulnerability found notification."""
    blocks: list[dict[str, Any]] = [
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
                "text": f"Security scan detected {'critical' if critical_count else 'high-priority'} "
                f"vulnerabilities in *{_escape_mrkdwn(project_name)}*.",
            },
        },
        {"type": "divider"},
    ]

    fields: list[dict[str, str]] = []
    if kev_count:
        fields.append({"type": "mrkdwn", "text": f"\u26a0\ufe0f *KEV Vulnerabilities:* {kev_count}"})
    if high_epss_count:
        fields.append({"type": "mrkdwn", "text": f"\U0001f4c8 *High EPSS ({HIGH_EPSS_LABEL}):* {high_epss_count}"})
    fields.append(
        {"type": "mrkdwn", "text": f"{SEVERITY_EMOJI['CRITICAL']} *{PRIORITY_VULNS_LABEL}:* {priority_count}"}
    )

    blocks.append({"type": "section", "fields": fields})

    if top_vulns:
        vuln_lines = [format_vuln_line(i, v, "_", _escape_mrkdwn) for i, v in enumerate(top_vulns, 1)]
        heading = f"*Top Priority Vulnerabilities ({len(top_vulns)} of {priority_count})*"
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": _fit(heading + "\n" + "\n".join(vuln_lines))},
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
    affected_projects: list[dict[str, Any]] | None = None,
    dashboard_link: str | None = None,
) -> list[dict[str, Any]]:
    """Build Block Kit layout for advisory / broadcast notifications."""
    body_slots = _MAX_BLOCKS - 2 - bool(affected_projects) - bool(dashboard_link)
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"\U0001f4e2 {subject}"[:_HEADER_MAX_LENGTH],
                "emoji": True,
            },
        },
        {"type": "divider"},
        *_section_blocks(_escape_mrkdwn(message), body_slots),
    ]

    if affected_projects:
        shown = affected_projects[:AFFECTED_PROJECTS_SHOWN]
        project_lines = [
            f"\u2022 *{_escape_mrkdwn(p['name'])}*: {_escape_mrkdwn(project_findings_summary(p['findings']))}"
            for p in shown
        ]

        heading = f"*Your Projects Using the Package ({len(shown)} of {len(affected_projects)})*"
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": _fit(heading + "\n" + "\n".join(project_lines))},
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
