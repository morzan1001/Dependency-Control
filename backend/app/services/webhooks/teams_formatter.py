"""Teams Adaptive Card formatter for webhook payloads."""

from typing import List, Optional


class TeamsFormatter:

    @staticmethod
    def _wrap_card(
        body: List[dict],
        actions: Optional[List[dict]] = None,
        summary: str = "DependencyControl",
    ) -> dict:
        card: dict = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.5",
            "summary": summary,
            "msteams": {"width": "Full"},
            "body": body,
        }
        if actions:
            card["actions"] = actions
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
        body = [
            {
                "type": "Container",
                "style": "accent",
                "items": [
                    {
                        "type": "TextBlock",
                        "size": "ExtraLarge",
                        "weight": "Bolder",
                        "text": "✅ Test Webhook",
                        "wrap": True,
                    },
                    {
                        "type": "TextBlock",
                        "text": "DependencyControl webhook is configured correctly.",
                        "wrap": True,
                    },
                ],
            }
        ]
        return TeamsFormatter._wrap_card(body, summary="DependencyControl test webhook")

    @staticmethod
    def build_generic_card(
        subject: str, message: str, url: Optional[str] = None
    ) -> dict:
        body = [
            {
                "type": "TextBlock",
                "size": "ExtraLarge",
                "weight": "Bolder",
                "text": subject,
                "wrap": True,
            },
            {
                "type": "TextBlock",
                "text": message,
                "wrap": True,
            },
        ]
        actions = [{"type": "Action.OpenUrl", "title": "View in DependencyControl", "url": url}] if url else None
        return TeamsFormatter._wrap_card(body, actions, summary=subject)

    @staticmethod
    def build_scan_completed_card(
        project_name: str,
        scan_id: str,
        findings: dict,
        scan_url: Optional[str] = None,
    ) -> dict:
        total = findings.get("total", 0)
        stats = findings.get("stats", {})

        container_style = "good" if total == 0 else "warning"

        facts = [
            {"title": "Project", "value": project_name},
            {"title": "Total Findings", "value": str(total)},
        ]
        for severity, count in stats.items():
            if count and int(count) > 0:
                facts.append({"title": severity.capitalize(), "value": str(count)})

        body = [
            {
                "type": "Container",
                "style": container_style,
                "items": [
                    {
                        "type": "TextBlock",
                        "size": "ExtraLarge",
                        "weight": "Bolder",
                        "text": "🔍 Scan Completed",
                        "wrap": True,
                    }
                ],
            },
            {"type": "FactSet", "facts": facts},
        ]
        actions = [{"type": "Action.OpenUrl", "title": "View Scan Results", "url": scan_url}] if scan_url else None
        return TeamsFormatter._wrap_card(body, actions, summary=f"Scan completed for {project_name}")

    @staticmethod
    def build_vulnerability_found_card(
        project_name: str,
        scan_id: str,
        vulns: dict,
        scan_url: Optional[str] = None,
    ) -> dict:
        critical = vulns.get("critical", 0)
        high = vulns.get("high", 0)
        kev = vulns.get("kev", 0)
        high_epss = vulns.get("high_epss", 0)
        top = vulns.get("top", [])

        container_style = "attention" if critical > 0 else "warning"

        facts = [
            {"title": "Project", "value": project_name},
            {"title": "Critical", "value": str(critical)},
            {"title": "High", "value": str(high)},
        ]
        if kev > 0:
            facts.append({"title": "Known Exploited (KEV)", "value": str(kev)})
        if high_epss > 0:
            facts.append({"title": "High EPSS", "value": str(high_epss)})

        body: List[dict] = [
            {
                "type": "Container",
                "style": container_style,
                "items": [
                    {
                        "type": "TextBlock",
                        "size": "ExtraLarge",
                        "weight": "Bolder",
                        "text": "🚨 Critical Vulnerabilities Found",
                        "wrap": True,
                    }
                ],
            },
            {"type": "FactSet", "facts": facts},
        ]

        if top:
            top_items: List[dict] = [
                {"type": "TextBlock", "text": "**Top Vulnerabilities**", "weight": "Bolder"}
            ]
            for vuln in top[:3]:
                cve_id = vuln.get("cve_id", "Unknown")
                severity = vuln.get("severity", "Unknown")
                component = vuln.get("component", "")
                top_items.append(
                    {"type": "TextBlock", "text": f"• **{cve_id}** ({severity}) — {component}", "wrap": True}
                )
            body.append({"type": "Container", "items": top_items})

        actions = [{"type": "Action.OpenUrl", "title": "View Vulnerabilities", "url": scan_url}] if scan_url else None
        return TeamsFormatter._wrap_card(body, actions, summary=f"Vulnerabilities found in {project_name}")

    @staticmethod
    def build_analysis_failed_card(
        project_name: str,
        error: str,
        scan_url: Optional[str] = None,
    ) -> dict:
        body = [
            {
                "type": "Container",
                "style": "attention",
                "items": [
                    {
                        "type": "TextBlock",
                        "size": "ExtraLarge",
                        "weight": "Bolder",
                        "text": "❌ Analysis Failed",
                        "wrap": True,
                    }
                ],
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Project", "value": project_name},
                    {"title": "Error", "value": error},
                ],
            },
        ]
        actions = [{"type": "Action.OpenUrl", "title": "View Details", "url": scan_url}] if scan_url else None
        return TeamsFormatter._wrap_card(body, actions, summary=f"Analysis failed for {project_name}")
