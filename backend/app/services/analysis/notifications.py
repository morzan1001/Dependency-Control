"""Notification handling and webhook triggers for completed and failed scans."""

import hashlib
import json
import logging
from typing import Any

from app.core.config import settings
from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    NOTIFICATION_EVENT_ANALYSIS_COMPLETED,
    NOTIFICATION_EVENT_ANALYSIS_FAILED,
    NOTIFICATION_EVENT_VULNERABILITY_FOUND,
    get_severity_value,
)
from app.core.cve import canonical_cve
from app.core.epss import HIGH_EPSS_LABEL, bucket_epss
from app.models.finding import Finding, FindingType
from app.models.project import Project
from app.schemas.notification import PRIORITY_VULNS_LABEL, AlertVulnerability
from app.services.analysis.types import Database
from app.services.notifications import notification_service
from app.services.notifications.mattermost_formatter import (
    build_analysis_completed_props as mm_analysis_props,
)
from app.services.notifications.mattermost_formatter import (
    build_vulnerability_found_props as mm_vulnerability_props,
)
from app.services.notifications.slack_formatter import (
    build_analysis_completed_blocks,
    build_vulnerability_found_blocks,
)
from app.services.notifications.service import safe_notify_project_event
from app.services.notifications.templates import (
    get_analysis_completed_template,
    get_vulnerability_found_template,
)
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

# Lines an alert lists before it starts naming a count instead; every channel says which it did.
_TOP_VULNS_SHOWN = 10


def _extract_vulnerability_info(entry_details: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    """Extract vulnerability info from a vulnerability entry and its parent finding."""
    return AlertVulnerability(
        id=canonical_cve(entry_details) or "Unknown",
        severity=entry_details["severity"],
        package=finding.get("component", "Unknown"),
        version=finding.get("version", ""),
        in_kev=entry_details.get(DETAILS_KEY_IN_KEV, False),
        epss_score=entry_details.get("epss_score"),
        kev_due_date=entry_details.get("kev_due_date"),
        kev_ransomware_use=entry_details.get(DETAILS_KEY_KEV_RANSOMWARE, False),
    ).model_dump()


def _is_high_epss(vuln: dict[str, Any]) -> bool:
    return bucket_epss(vuln["epss_score"] or 0) == "high"


def _is_priority(vuln: dict[str, Any]) -> bool:
    return vuln["severity"] in ("CRITICAL", "HIGH") or vuln["in_kev"] or _is_high_epss(vuln)


def _categorize_vulnerabilities(
    vulnerability_findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Categorize vulnerabilities into (kev_vulns, high_epss_vulns, priority_vulns)."""
    vulns = [
        _extract_vulnerability_info(entry_details, finding)
        for finding in vulnerability_findings
        for entry_details in (finding.get("details") or {}).get("vulnerabilities") or []
    ]
    return (
        [v for v in vulns if v["in_kev"]],
        [v for v in vulns if _is_high_epss(v)],
        [v for v in vulns if _is_priority(v)],
    )


def _format_vuln_line(index: int, vuln: dict[str, Any]) -> str:
    """Format a single vulnerability line for notification message."""
    vuln_line = f"  {index}. {vuln['id']} ({vuln['severity']}) - {vuln['package']}"
    if vuln["version"]:
        vuln_line += f"@{vuln['version']}"
    if vuln.get("in_kev"):
        vuln_line += " [KEV]"
    if vuln.get("epss_score"):
        vuln_line += f" [EPSS: {vuln['epss_score'] * 100:.1f}%]"
    return vuln_line


def _build_vulnerability_message(
    project_name: str,
    kev_vulns: list[dict[str, Any]],
    high_epss_vulns: list[dict[str, Any]],
    priority_vulns: list[dict[str, Any]],
    top_vulns: list[dict[str, Any]],
    scan_link: str,
) -> tuple[str, str]:
    """Build (subject, message) for a vulnerability notification."""
    subject = "[SECURITY ALERT] "
    if kev_vulns:
        subject += f"{len(kev_vulns)} KEV Vulnerabilities in {project_name}"
    elif high_epss_vulns:
        subject += f"High-Risk Vulnerabilities in {project_name}"
    else:
        subject += f"Critical Vulnerabilities in {project_name}"

    message = f"Security scan detected critical vulnerabilities in {project_name}.\n\n"

    if kev_vulns:
        message += f"[KEV] {len(kev_vulns)} Known Exploited Vulnerabilities (CISA KEV)\n"
    if high_epss_vulns:
        message += (
            f"[HIGH RISK] {len(high_epss_vulns)} vulnerabilities with high exploitation probability "
            f"({HIGH_EPSS_LABEL})\n"
        )
    message += f"\n{PRIORITY_VULNS_LABEL}: {len(priority_vulns)}\n"

    if top_vulns:
        message += f"\nTop Priority Vulnerabilities ({len(top_vulns)} of {len(priority_vulns)}):\n"
        for i, vuln in enumerate(top_vulns, 1):
            message += _format_vuln_line(i, vuln) + "\n"

    message += f"\nView full report: {scan_link}"

    return subject, message


async def _first_announcement(db: Database, scan_id: str, event: str, content: Any) -> bool:
    """Claim ``event`` for ``content`` on the scan, so a re-analysis that changed nothing announces nothing."""
    fingerprint = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    claimed = await db.scans.find_one_and_update(
        {"_id": scan_id, f"announced.{event}": {"$ne": fingerprint}},
        {"$set": {f"announced.{event}": fingerprint}},
    )
    return claimed is not None


async def send_scan_notifications(
    scan_id: str,
    project: Project,
    aggregated_findings: list[Finding],
    results_summary: list[str],
    db: Database,
) -> None:
    """Send notifications and trigger webhooks for a completed scan.

    Each notification type is handled independently so one failure does not block others.
    """
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in aggregated_findings:
        if f.type != FindingType.SYSTEM_WARNING and f.severity in severity_counts:
            severity_counts[f.severity] += 1

    scan = await db.scans.find_one({"_id": scan_id}) or {}
    completion = [len(aggregated_findings), severity_counts, scan.get("status"), scan.get("failed_analyzers")]
    if await _first_announcement(db, scan_id, NOTIFICATION_EVENT_ANALYSIS_COMPLETED, completion):
        try:
            scan_link = f"{settings.FRONTEND_BASE_URL}/projects/{project.id}/scans/{scan_id}"
            html_content = get_analysis_completed_template(
                analysis_link=scan_link,
                project_name_scanned=project.name,
                total_findings=len(aggregated_findings),
                severity_critical=severity_counts["CRITICAL"],
                severity_high=severity_counts["HIGH"],
                severity_medium=severity_counts["MEDIUM"],
                severity_low=severity_counts["LOW"],
                analyzer_count=len(results_summary),
                results_summary=results_summary,
            )

            results_text = "\n".join(results_summary) if results_summary else "No analyzer details available."
            slack_blocks = build_analysis_completed_blocks(
                project_name=project.name,
                scan_id=scan_id,
                total_findings=len(aggregated_findings),
                severity_counts=severity_counts,
                results_summary=results_summary,
                scan_link=scan_link,
            )
            mm_props = mm_analysis_props(
                project_name=project.name,
                scan_id=scan_id,
                total_findings=len(aggregated_findings),
                severity_counts=severity_counts,
                results_summary=results_summary,
                scan_link=scan_link,
            )
            await notification_service.notify_project_members(
                project=project,
                event_type=NOTIFICATION_EVENT_ANALYSIS_COMPLETED,
                subject=f"Analysis Completed: {project.name}",
                message=(
                    f"Scan {scan_id} completed.\nFound {len(aggregated_findings)} issues.\nResults:\n{results_text}"
                ),
                db=db,
                html_message=html_content,
                slack_blocks=slack_blocks,
                mattermost_props=mm_props,
            )
        except Exception as e:
            logger.exception("Failed to send analysis_completed notification: %s", e)

        try:
            await webhook_service.trigger_scan_completed(
                db=db,
                scan_id=scan_id,
                project_id=str(project.id),
                project_name=project.name,
                findings_count=len(aggregated_findings),
                stats=scan.get("stats", {}),
                scan_status=scan.get("status", "completed"),
                failed_analyzers=scan.get("failed_analyzers") or [],
            )
        except Exception as e:
            logger.exception("Failed to trigger scan_completed webhook: %s", e)

    try:
        vulnerability_findings = [f.model_dump() for f in aggregated_findings if f.type == "vulnerability"]

        if not vulnerability_findings:
            return

        kev_vulns, high_epss_vulns, priority_vulns = _categorize_vulnerabilities(vulnerability_findings)
        if not priority_vulns:
            return
        alerted = sorted({(v["id"], v["package"], v["version"], v["in_kev"]) for v in priority_vulns})
        if not await _first_announcement(db, scan_id, NOTIFICATION_EVENT_VULNERABILITY_FOUND, alerted):
            return

        # Order: KEV first, then higher EPSS, then more severe.
        top_vulns = sorted(
            priority_vulns,
            key=lambda x: (
                not x.get("in_kev", False),
                -(x.get("epss_score") or 0),
                -get_severity_value(x.get("severity")),
            ),
        )[:_TOP_VULNS_SHOWN]

        scan_link = f"{settings.FRONTEND_BASE_URL}/projects/{project.id}/scans/{scan_id}"
        subject, message = _build_vulnerability_message(
            project.name,
            kev_vulns,
            high_epss_vulns,
            priority_vulns,
            top_vulns,
            scan_link,
        )

        vuln_html = get_vulnerability_found_template(
            report_link=scan_link,
            project_name_scanned=project.name,
            vulnerabilities=top_vulns,
            priority_count=len(priority_vulns),
            has_kev=bool(kev_vulns),
            kev_count=len(kev_vulns),
            kev_vulnerabilities=kev_vulns,
            has_high_epss=bool(high_epss_vulns),
            high_epss_count=len(high_epss_vulns),
        )

        vuln_slack_blocks = build_vulnerability_found_blocks(
            project_name=project.name,
            kev_count=len(kev_vulns),
            high_epss_count=len(high_epss_vulns),
            priority_count=len(priority_vulns),
            top_vulns=top_vulns,
            scan_link=scan_link,
        )
        vuln_mm_props = mm_vulnerability_props(
            project_name=project.name,
            kev_count=len(kev_vulns),
            high_epss_count=len(high_epss_vulns),
            priority_count=len(priority_vulns),
            top_vulns=top_vulns,
            scan_link=scan_link,
        )
        await notification_service.notify_project_members(
            project=project,
            event_type=NOTIFICATION_EVENT_VULNERABILITY_FOUND,
            subject=subject,
            message=message,
            db=db,
            html_message=vuln_html,
            slack_blocks=vuln_slack_blocks,
            mattermost_props=vuln_mm_props,
        )

        logger.info(
            f"Sent vulnerability_found notification for project {project.name}: "
            f"{len(kev_vulns)} KEV, {len(high_epss_vulns)} high EPSS, "
            f"{len(priority_vulns)} priority"
        )

        try:
            await webhook_service.trigger_vulnerability_found(
                db=db,
                scan_id=scan_id,
                project_id=str(project.id),
                project_name=project.name,
                critical_count=sum(1 for v in priority_vulns if v["severity"] == "CRITICAL"),
                high_count=sum(1 for v in priority_vulns if v["severity"] == "HIGH"),
                kev_count=len(kev_vulns),
                high_epss_count=len(high_epss_vulns),
                top_vulnerabilities=top_vulns,
            )
        except Exception as e:
            logger.exception("Failed to trigger vulnerability_found webhook: %s", e)

    except Exception as e:
        logger.exception("Failed to process vulnerability notifications: %s", e)


async def notify_analysis_failed(db: Database, scan_id: str, project_id: str | None, error: str) -> None:
    """Send the analysis_failed webhook and member notification; errors are logged, never raised."""
    try:
        project = await db.projects.find_one({"_id": project_id})
        if not project:
            return
        project_name = project.get("name", "Unknown")
        await webhook_service.trigger_analysis_failed(
            db=db,
            scan_id=scan_id,
            project_id=str(project["_id"]),
            project_name=project_name,
            error_message=error,
        )
        await safe_notify_project_event(
            db,
            project_id=str(project["_id"]),
            event_type=NOTIFICATION_EVENT_ANALYSIS_FAILED,
            subject=f"Scan failed: {project_name}",
            message=f"Scan {scan_id} for project {project_name} failed: {error}",
            context="analysis.analysis_failed",
        )
    except Exception:
        logger.exception("Failed to announce the failure of scan %s", scan_id)
