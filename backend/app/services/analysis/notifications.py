"""
Notification handling for completed scans.

Sends notifications and triggers webhooks when scans complete.
"""

import logging
from typing import Any, Dict, List

from app.models.finding import Finding
from app.models.project import Project
from app.services.notifications import notification_service
from app.services.webhooks import webhook_service
from app.services.analysis.types import Database

logger = logging.getLogger(__name__)


# Severity sort order for prioritizing vulnerabilities
SEVERITY_ORDER: Dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _extract_vulnerability_info(
    vuln: Dict[str, Any], finding: Dict[str, Any]
) -> Dict[str, Any]:
    """Extract vulnerability info from a vulnerability dict and its parent finding."""
    return {
        "id": vuln.get("id", finding.get("id", "Unknown")),
        "severity": vuln.get("severity", finding.get("severity", "UNKNOWN")),
        "package": finding.get("component", "Unknown"),
        "version": finding.get("version", ""),
        "in_kev": vuln.get("in_kev", False),
        "epss_score": vuln.get("epss_score"),
        "kev_due_date": vuln.get("kev_due_date"),
        "kev_ransomware_use": vuln.get("kev_ransomware_use", False),
    }


def _categorize_vulnerabilities(
    vulnerability_findings: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Categorize vulnerabilities into KEV, high EPSS, and critical/high severity.

    Returns:
        Tuple of (kev_vulns, high_epss_vulns, critical_vulns)
    """
    kev_vulns: List[Dict[str, Any]] = []
    high_epss_vulns: List[Dict[str, Any]] = []
    critical_vulns: List[Dict[str, Any]] = []

    for finding in vulnerability_findings:
        details = finding.get("details", {})
        vulns = details.get("vulnerabilities", [details])

        for vuln in vulns:
            vuln_info = _extract_vulnerability_info(vuln, finding)

            if vuln.get("in_kev"):
                kev_vulns.append(vuln_info)

            epss_score = vuln.get("epss_score")
            if epss_score is not None and epss_score >= 0.1:
                high_epss_vulns.append(vuln_info)

            severity = vuln.get("severity")
            if severity in ["CRITICAL", "HIGH"] or vuln.get("in_kev"):
                critical_vulns.append(vuln_info)

    return kev_vulns, high_epss_vulns, critical_vulns


def _build_vulnerability_message(
    project_name: str,
    kev_vulns: List[Dict[str, Any]],
    high_epss_vulns: List[Dict[str, Any]],
    critical_vulns: List[Dict[str, Any]],
    top_vulns: List[Dict[str, Any]],
    scan_id: str,
) -> tuple[str, str]:
    """
    Build subject and message for vulnerability notification.

    Returns:
        Tuple of (subject, message)
    """
    # Build subject
    subject = "[SECURITY ALERT] "
    if kev_vulns:
        subject += f"{len(kev_vulns)} KEV Vulnerabilities in {project_name}"
    elif high_epss_vulns:
        subject += f"High-Risk Vulnerabilities in {project_name}"
    else:
        subject += f"Critical Vulnerabilities in {project_name}"

    # Build message
    message = f"Security scan detected critical vulnerabilities in {project_name}.\n\n"

    if kev_vulns:
        message += (
            f"[KEV] {len(kev_vulns)} Known Exploited Vulnerabilities (CISA KEV)\n"
        )
    if high_epss_vulns:
        message += (
            f"[HIGH RISK] {len(high_epss_vulns)} vulnerabilities with "
            "high exploitation probability (EPSS > 10%)\n"
        )
    message += f"\nTotal critical/high vulnerabilities: {len(critical_vulns)}\n"

    # Add top vulnerabilities details
    if top_vulns:
        message += "\nTop Priority Vulnerabilities:\n"
        for i, vuln in enumerate(top_vulns, 1):
            vuln_line = f"  {i}. {vuln['id']} ({vuln['severity']})"
            vuln_line += f" - {vuln['package']}"
            if vuln["version"]:
                vuln_line += f"@{vuln['version']}"
            if vuln.get("in_kev"):
                vuln_line += " [KEV]"
            if vuln.get("epss_score"):
                vuln_line += f" [EPSS: {vuln['epss_score']*100:.1f}%]"
            message += vuln_line + "\n"

    message += f"\nView full report: {scan_id}"

    return subject, message


async def send_scan_notifications(
    scan_id: str,
    project: Project,
    aggregated_findings: List[Finding],
    results_summary: List[str],
    db: Database,
) -> None:
    """
    Send notifications and trigger webhooks for completed scan.

    Each notification type is handled independently to prevent one failure
    from blocking others.

    Args:
        scan_id: The scan ID
        project: The project model
        aggregated_findings: List of Finding objects from the aggregator
        results_summary: List of analyzer result strings
        db: Database connection
    """
    # Send analysis_completed notification
    try:
        await notification_service.notify_project_members(
            project=project,
            event_type="analysis_completed",
            subject=f"Analysis Completed: {project.name}",
            message=(
                f"Scan {scan_id} completed.\n"
                f"Found {len(aggregated_findings)} issues.\n"
                f"Results:\n" + "\n".join(results_summary)
            ),
            db=db,
        )
    except Exception as e:
        logger.error(f"Failed to send analysis_completed notification: {e}")

    # Trigger scan_completed webhook
    try:
        scan = await db.scans.find_one({"_id": scan_id})
        if scan:
            stats = scan.get("stats", {})
            await webhook_service.trigger_scan_completed(
                db=db,
                scan_id=scan_id,
                project_id=str(project.id),
                project_name=project.name,
                findings_count=len(aggregated_findings),
                stats=stats,
            )
    except Exception as e:
        logger.error(f"Failed to trigger scan_completed webhook: {e}")

    # Check for critical vulnerabilities and send vulnerability_found notification
    try:
        # Convert Finding objects to dicts for processing
        vulnerability_findings = [
            f.model_dump() for f in aggregated_findings if f.type == "vulnerability"
        ]

        if not vulnerability_findings:
            return

        # Categorize vulnerabilities
        kev_vulns, high_epss_vulns, critical_vulns = _categorize_vulnerabilities(
            vulnerability_findings
        )

        # Send notification if there are significant vulnerabilities
        if kev_vulns or high_epss_vulns or critical_vulns:
            # Sort and get top 10 most critical vulnerabilities
            top_vulns = sorted(
                critical_vulns,
                key=lambda x: (
                    not x.get("in_kev", False),  # KEV first
                    -(x.get("epss_score") or 0),  # Then by EPSS
                    SEVERITY_ORDER.get(x.get("severity", "LOW"), 4),
                ),
            )[:10]

            subject, message = _build_vulnerability_message(
                project.name,
                kev_vulns,
                high_epss_vulns,
                critical_vulns,
                top_vulns,
                scan_id,
            )

            await notification_service.notify_project_members(
                project=project,
                event_type="vulnerability_found",
                subject=subject,
                message=message,
                db=db,
            )

            logger.info(
                f"Sent vulnerability_found notification for project {project.name}: "
                f"{len(kev_vulns)} KEV, {len(high_epss_vulns)} high EPSS, "
                f"{len(critical_vulns)} critical/high"
            )

            # Trigger vulnerability_found webhook
            try:
                await webhook_service.trigger_vulnerability_found(
                    db=db,
                    scan_id=scan_id,
                    project_id=str(project.id),
                    project_name=project.name,
                    critical_count=sum(
                        1 for v in critical_vulns if v.get("severity") == "CRITICAL"
                    ),
                    high_count=sum(
                        1 for v in critical_vulns if v.get("severity") == "HIGH"
                    ),
                    kev_count=len(kev_vulns),
                    high_epss_count=len(high_epss_vulns),
                    top_vulnerabilities=top_vulns,
                )
            except Exception as e:
                logger.error(f"Failed to trigger vulnerability_found webhook: {e}")

    except Exception as e:
        logger.error(f"Failed to process vulnerability notifications: {e}")
