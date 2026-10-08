"""Teams Adaptive Card formatter for webhook payloads."""

from collections.abc import Mapping
from typing import Any

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.finding import Severity
from app.schemas.notification import AlertVulnerability, scan_alert_level
from app.services.webhooks.messages import policy_change_text

_SEVERITY_KEYS = tuple(s.value.lower() for s in Severity)
_ALERT_STYLE = {"critical": "attention", "warning": "warning", "ok": "good"}


def _header(style: str, title: str, *items: dict) -> dict:
    title_block = {"type": "TextBlock", "size": "ExtraLarge", "weight": "Bolder", "text": title, "wrap": True}
    return {"type": "Container", "style": style, "items": [title_block, *items]}


def _facts(facts: Mapping[str, object]) -> dict:
    return {"type": "FactSet", "facts": [{"title": title, "value": str(value)} for title, value in facts.items()]}


class TeamsFormatter:
    @staticmethod
    def _wrap_card(body: list[dict], summary: str, link: tuple[str, str] | None = None) -> dict:
        card: dict = {
            "type": "AdaptiveCard",
            # Adaptive Card schema identifier, not fetched at runtime.
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",  # NOSONAR
            "version": "1.5",
            "summary": summary,
            "msteams": {"width": "Full"},
            "body": body,
        }
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": link[0], "url": link[1]}]
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": card,
                }
            ],
        }

    @staticmethod
    def build_test_card() -> dict:
        message = {"type": "TextBlock", "text": "DependencyControl webhook is configured correctly.", "wrap": True}
        return TeamsFormatter._wrap_card(
            [_header("accent", "✅ Test Webhook", message)], summary="DependencyControl test webhook"
        )

    @staticmethod
    def build_generic_card(event: str, message: str) -> dict:
        title = event.replace(".", " ").replace("_", " ").title()
        body = [
            {"type": "TextBlock", "size": "ExtraLarge", "weight": "Bolder", "text": title, "wrap": True},
            {"type": "TextBlock", "text": message, "wrap": True},
        ]
        return TeamsFormatter._wrap_card(body, summary=title)

    @staticmethod
    def build_policy_changed_card(event: str, payload: Mapping[str, Any]) -> dict:
        return TeamsFormatter.build_generic_card(event, policy_change_text(payload))

    @staticmethod
    def build_scan_completed_card(payload: Mapping[str, Any]) -> dict:
        project_name = payload["project"]["name"]
        stats = payload["findings"]["stats"]
        style = _ALERT_STYLE[scan_alert_level(stats["critical"], stats["high"])]
        title = "🔍 Scan Completed"
        facts = {"Project": project_name, "Total Findings": payload["findings"]["total"]}
        facts |= {key.title(): stats[key] for key in _SEVERITY_KEYS if stats[key]}
        if payload["scan_status"] != SCAN_STATUS_COMPLETED:
            style = "attention" if style == "attention" else "warning"
            title = "⚠️ Scan Completed with Errors"
            facts["Failed Analyzers"] = ", ".join(payload["failed_analyzers"])

        return TeamsFormatter._wrap_card(
            [_header(style, title), _facts(facts)],
            summary=f"Scan completed for {project_name}",
            link=("View Scan Results", payload["scan"]["url"]),
        )

    @staticmethod
    def build_vulnerability_found_card(payload: Mapping[str, Any]) -> dict:
        project_name = payload["project"]["name"]
        vulns = payload["vulnerabilities"]
        if vulns["critical"]:
            title = "🚨 Critical Vulnerabilities Found"
        elif vulns["high"]:
            title = "⚠️ High Vulnerabilities Found"
        elif vulns["kev"]:
            title = "⚠️ Known Exploited Vulnerability Found"
        else:
            title = "⚠️ High-EPSS Vulnerability Found"

        facts = {"Project": project_name, "Critical": vulns["critical"], "High": vulns["high"]}
        if vulns["kev"]:
            facts["Known Exploited (KEV)"] = vulns["kev"]
        if vulns["high_epss"]:
            facts["High EPSS"] = vulns["high_epss"]
        body = [_header("attention" if vulns["critical"] else "warning", title), _facts(facts)]

        top = [AlertVulnerability.model_validate(raw) for raw in vulns["top"]]
        if top:
            heading = f"**Top Priority Vulnerabilities ({len(top)} of {vulns['priority']})**"
            lines = [
                f"{i}. **{v.id}** ({v.severity}) — {v.versioned_package}" + "".join(f" [{tag}]" for tag in v.tags)
                for i, v in enumerate(top, 1)
            ]
            items: list[dict] = [{"type": "TextBlock", "text": heading, "weight": "Bolder"}]
            items += [{"type": "TextBlock", "text": line, "wrap": True} for line in lines]
            body.append({"type": "Container", "items": items})

        return TeamsFormatter._wrap_card(
            body,
            summary=f"Vulnerabilities found in {project_name}",
            link=("View Vulnerabilities", payload["scan"]["url"]),
        )

    @staticmethod
    def build_analysis_failed_card(payload: Mapping[str, Any]) -> dict:
        project_name = payload["project"]["name"]
        return TeamsFormatter._wrap_card(
            [_header("attention", "❌ Analysis Failed"), _facts({"Project": project_name, "Error": payload["error"]})],
            summary=f"Analysis failed for {project_name}",
            link=("View Details", payload["scan"]["url"]),
        )
