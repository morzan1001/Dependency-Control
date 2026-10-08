"""Slack incoming-webhook messages for the webhook events."""

from collections.abc import Mapping
from typing import Any

from app.core.constants import (
    WEBHOOK_EVENT_ANALYSIS_FAILED,
    WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED,
    WEBHOOK_EVENT_LICENSE_POLICY_CHANGED,
    WEBHOOK_EVENT_SCAN_COMPLETED,
    WEBHOOK_EVENT_VULNERABILITY_FOUND,
)
from app.schemas.notification import AlertVulnerability
from app.services.notifications.slack_formatter import (
    _escape_mrkdwn,
    build_analysis_completed_blocks,
    build_generic_blocks,
    build_vulnerability_found_blocks,
)
from app.services.webhooks.messages import event_summary, policy_change_text

_TEST_TEXT = "DependencyControl webhook is configured correctly."


def _message(text: str, blocks: list[dict[str, Any]]) -> dict[str, Any]:
    # Notifications and clients without Block Kit show only the text.
    return {"text": _escape_mrkdwn(text), "blocks": blocks}


def build_slack_test_message() -> dict[str, Any]:
    return _message(_TEST_TEXT, build_generic_blocks("Test Webhook", _TEST_TEXT))


def build_slack_message(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    project_name = payload.get("project", {}).get("name", "Unknown Project")
    if event_type == WEBHOOK_EVENT_SCAN_COMPLETED:
        stats = payload["findings"]["stats"]
        failed = payload["failed_analyzers"]
        return _message(
            f"Analysis completed: {project_name}",
            build_analysis_completed_blocks(
                project_name=project_name,
                scan_id=payload["scan"]["id"],
                total_findings=payload["findings"]["total"],
                severity_counts={level.upper(): stats.get(level, 0) for level in ("critical", "high", "medium", "low")},
                results_summary=[f"{name}: failed" for name in failed],
                analyzer_count=len(failed),
                scan_link=payload["scan"]["url"],
            ),
        )
    if event_type == WEBHOOK_EVENT_VULNERABILITY_FOUND:
        vulns = payload["vulnerabilities"]
        return _message(
            f"Security alert: {project_name}",
            build_vulnerability_found_blocks(
                project_name=project_name,
                kev_count=vulns["kev"],
                high_epss_count=vulns["high_epss"],
                priority_count=vulns["priority"],
                critical_count=vulns["critical"],
                top_vulns=[AlertVulnerability.model_validate(raw) for raw in vulns["top"]],
                scan_link=payload["scan"]["url"],
            ),
        )
    if event_type == WEBHOOK_EVENT_ANALYSIS_FAILED:
        subject = f"Analysis failed: {project_name}"
        return _message(subject, build_generic_blocks(subject, f"{payload['error']}\n{payload['scan']['url']}"))
    if event_type in (WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED, WEBHOOK_EVENT_LICENSE_POLICY_CHANGED):
        text = policy_change_text(payload)
        return _message(text, build_generic_blocks(event_type, text))
    subject, details = event_summary(event_type, payload)
    return _message(subject, build_generic_blocks(event_type, details))
