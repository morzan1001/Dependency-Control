import hashlib
import json
import logging
from typing import Any

from pymongo import ReturnDocument

from app.core.config import scan_link
from app.core.constants import (
    DETAILS_KEY_IN_KEV,
    DETAILS_KEY_KEV_RANSOMWARE,
    NOTIFICATION_EVENT_ANALYSIS_COMPLETED,
    NOTIFICATION_EVENT_ANALYSIS_FAILED,
    NOTIFICATION_EVENT_VULNERABILITY_FOUND,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
    ScanStatus,
    get_severity_value,
)
from app.core.cve import canonical_cve
from app.core.epss import HIGH_EPSS_LABEL, bucket_epss
from app.models.project import Project
from app.models.stats import Stats
from app.repositories.system_settings import SystemSettingsRepository
from app.schemas.notification import PRIORITY_VULNS_LABEL, AlertVulnerability
from app.services.analysis.registry import POST_PROCESSOR_ANALYZERS
from app.services.analysis.runner import AnalyzerOutcome
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
from app.services.recommendation.common import live_advisories
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

# Lines an alert lists before it starts naming a count instead; every channel says which it did.
_TOP_VULNS_SHOWN = 10


def _extract_vulnerability_info(entry_details: dict[str, Any], finding: dict[str, Any]) -> AlertVulnerability:
    return AlertVulnerability(
        id=canonical_cve(entry_details) or "Unknown",
        severity=entry_details["severity"],
        package=finding.get("component", "Unknown"),
        version=finding.get("version") or "",
        in_kev=entry_details.get(DETAILS_KEY_IN_KEV, False),
        epss_score=entry_details.get("epss_score"),
        kev_due_date=entry_details.get("kev_due_date"),
        kev_ransomware_use=entry_details.get(DETAILS_KEY_KEV_RANSOMWARE, False),
    )


def _is_high_epss(vuln: AlertVulnerability) -> bool:
    return bucket_epss(vuln.epss_score or 0) == "high"


def _is_priority(vuln: AlertVulnerability) -> bool:
    return vuln.severity in ("CRITICAL", "HIGH") or vuln.in_kev or _is_high_epss(vuln)


def _categorize_vulnerabilities(
    vulnerability_findings: list[dict[str, Any]],
) -> tuple[list[AlertVulnerability], list[AlertVulnerability], list[AlertVulnerability]]:
    vulns = [
        _extract_vulnerability_info(entry_details, finding)
        for finding in vulnerability_findings
        for entry_details in live_advisories(finding.get("details"))
    ]
    return (
        [v for v in vulns if v.in_kev],
        [v for v in vulns if _is_high_epss(v)],
        [v for v in vulns if _is_priority(v)],
    )


def _build_vulnerability_message(
    project_name: str,
    kev_vulns: list[AlertVulnerability],
    high_epss_vulns: list[AlertVulnerability],
    priority_vulns: list[AlertVulnerability],
    critical_count: int,
    top_vulns: list[AlertVulnerability],
    link: str,
) -> tuple[str, str]:
    alarm = "critical" if critical_count else "high-priority"
    subject = "[SECURITY ALERT] "
    if kev_vulns:
        subject += f"{len(kev_vulns)} KEV Vulnerabilities in {project_name}"
    elif high_epss_vulns:
        subject += f"High-Risk Vulnerabilities in {project_name}"
    else:
        subject += f"{alarm.title()} Vulnerabilities in {project_name}"

    message = f"Security scan detected {alarm} vulnerabilities in {project_name}.\n\n"

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
            tags = "".join(f" [{tag}]" for tag in vuln.tags)
            message += f"  {i}. {vuln.id} ({vuln.severity}) - {vuln.versioned_package}{tags}\n"

    message += f"\nView full report: {link}"

    return subject, message


def _completion_warning(status: ScanStatus, failed_analyzers: list[str]) -> str | None:
    if status != SCAN_STATUS_COMPLETED_WITH_ERRORS:
        return None
    failed = f" ({', '.join(failed_analyzers)})" if failed_analyzers else ""
    return f"Completed with errors{failed}: results may be incomplete."


async def _announcement_revision(db: Database, scan_id: str, event: str, content: Any) -> int | None:
    """Claim ``event`` for ``content`` on the scan; None when a re-analysis changed nothing to announce."""
    fingerprint = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    revision = f"announced_revisions.{event}"
    claimed = await db.scans.find_one_and_update(
        {"_id": scan_id, f"announced.{event}": {"$ne": fingerprint}},
        {"$set": {f"announced.{event}": fingerprint}, "$inc": {revision: 1}},
        projection={revision: 1},
        return_document=ReturnDocument.AFTER,
    )
    return None if claimed is None else int(claimed["announced_revisions"][event])


async def send_scan_notifications(
    scan_id: str,
    project: Project,
    findings: list[dict[str, Any]],
    stats: Stats,
    status: ScanStatus,
    failed_analyzers: list[str],
    analyzer_outcomes: list[AnalyzerOutcome],
    db: Database,
) -> None:
    """Each notification type is handled independently so one failure does not block the others."""
    link = scan_link(str(project.id), scan_id)
    severity_counts = {"CRITICAL": stats.critical, "HIGH": stats.high, "MEDIUM": stats.medium, "LOW": stats.low}
    completion = [len(findings), severity_counts, status, failed_analyzers]
    revision = await _announcement_revision(db, scan_id, NOTIFICATION_EVENT_ANALYSIS_COMPLETED, completion)
    if revision is not None:
        results_summary = [str(outcome) for outcome in analyzer_outcomes]
        analyzer_count = sum(1 for outcome in analyzer_outcomes if outcome.name not in POST_PROCESSOR_ANALYZERS)
        warning = _completion_warning(status, failed_analyzers)
        try:
            brand = (await SystemSettingsRepository(db).get()).brand
            html_content = get_analysis_completed_template(
                analysis_link=link,
                project_name_scanned=project.name,
                total_findings=len(findings),
                analyzer_count=analyzer_count,
                severity_critical=stats.critical,
                severity_high=stats.high,
                severity_medium=stats.medium,
                severity_low=stats.low,
                results_summary=results_summary,
                brand=brand,
                warning=warning,
            )

            results_text = "\n".join(results_summary) if results_summary else "No analyzer details available."
            completed_card: dict[str, Any] = {
                "project_name": project.name,
                "scan_id": scan_id,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "results_summary": results_summary,
                "analyzer_count": analyzer_count,
                "scan_link": link,
                "warning": warning,
            }
            outcome_line = f"Scan {scan_id} completed." + (f"\n{warning}" if warning else "")
            await notification_service.notify_project_members(
                project=project,
                event_type=NOTIFICATION_EVENT_ANALYSIS_COMPLETED,
                subject=f"Analysis Completed: {project.name}",
                message=f"{outcome_line}\nFound {len(findings)} issues.\nResults:\n{results_text}",
                db=db,
                html_message=html_content,
                slack_blocks=build_analysis_completed_blocks(**completed_card),
                mattermost_props=mm_analysis_props(**completed_card),
            )
        except Exception as e:
            logger.exception("Failed to send analysis_completed notification: %s", e)

        await webhook_service.trigger_scan_completed(
            db=db,
            scan_id=scan_id,
            project_id=str(project.id),
            project_name=project.name,
            findings_count=len(findings),
            stats=stats.model_dump(),
            scan_status=status,
            failed_analyzers=failed_analyzers,
            revision=revision,
            team_ids=project.team_ids,
        )

    try:
        vulnerability_findings = [f for f in findings if f["type"] == "vulnerability"]

        if not vulnerability_findings:
            return

        kev_vulns, high_epss_vulns, priority_vulns = _categorize_vulnerabilities(vulnerability_findings)
        if not priority_vulns:
            return
        alerted = sorted({(v.id, v.package, v.version, v.in_kev) for v in priority_vulns})
        if await _announcement_revision(db, scan_id, NOTIFICATION_EVENT_VULNERABILITY_FOUND, alerted) is None:
            return

        top_vulns = sorted(
            priority_vulns,
            key=lambda v: (not v.in_kev, -(v.epss_score or 0), -get_severity_value(v.severity)),
        )[:_TOP_VULNS_SHOWN]
        critical_count = sum(1 for v in priority_vulns if v.severity == "CRITICAL")

        subject, message = _build_vulnerability_message(
            project.name,
            kev_vulns,
            high_epss_vulns,
            priority_vulns,
            critical_count,
            top_vulns,
            link,
        )

        brand = (await SystemSettingsRepository(db).get()).brand
        vuln_html = get_vulnerability_found_template(
            report_link=link,
            project_name_scanned=project.name,
            vulnerabilities=top_vulns,
            priority_count=len(priority_vulns),
            kev_count=len(kev_vulns),
            kev_vulnerabilities=kev_vulns,
            high_epss_count=len(high_epss_vulns),
            brand=brand,
        )

        vulnerability_card: dict[str, Any] = {
            "project_name": project.name,
            "kev_count": len(kev_vulns),
            "high_epss_count": len(high_epss_vulns),
            "priority_count": len(priority_vulns),
            "critical_count": critical_count,
            "top_vulns": top_vulns,
            "scan_link": link,
        }
        await notification_service.notify_project_members(
            project=project,
            event_type=NOTIFICATION_EVENT_VULNERABILITY_FOUND,
            subject=subject,
            message=message,
            db=db,
            html_message=vuln_html,
            slack_blocks=build_vulnerability_found_blocks(**vulnerability_card),
            mattermost_props=mm_vulnerability_props(**vulnerability_card),
        )

        logger.info(
            f"Sent vulnerability_found notification for project {project.name}: "
            f"{len(kev_vulns)} KEV, {len(high_epss_vulns)} high EPSS, "
            f"{len(priority_vulns)} priority"
        )

        await webhook_service.trigger_vulnerability_found(
            db=db,
            scan_id=scan_id,
            project_id=str(project.id),
            project_name=project.name,
            critical_count=critical_count,
            high_count=sum(1 for v in priority_vulns if v.severity == "HIGH"),
            kev_count=len(kev_vulns),
            high_epss_count=len(high_epss_vulns),
            priority_count=len(priority_vulns),
            top_vulnerabilities=[v.model_dump() for v in top_vulns],
            team_ids=project.team_ids,
        )

    except Exception as e:
        logger.exception("Failed to process vulnerability notifications: %s", e)


async def notify_analysis_failed(db: Database, scan_id: str, project_id: str | None, error: str) -> None:
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
