import logging
from typing import Any, List

from app.services.notifications import notification_service
from app.services.webhooks import webhook_service
from app.models.project import Project

logger = logging.getLogger(__name__)


async def send_scan_notifications(
    scan_id: str,
    project: Project,
    aggregated_findings: List[Any],
    results_summary: List[str],
    db,
):
    """
    Send notifications and trigger webhooks for completed scan.
    """
    try:
        # Always send analysis_completed notification
        await notification_service.notify_project_members(
            project=project,
            event_type="analysis_completed",
            subject=f"Analysis Completed: {project.name}",
            message=f"Scan {scan_id} completed.\nFound {len(aggregated_findings)} issues.\nResults:\n"
            + "\n".join(results_summary),
            db=db,
        )

        # Trigger scan_completed webhook
        # Get scan stats for webhook payload
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

        # Check for critical vulnerabilities and send vulnerability_found notification
        # Convert Finding objects to dicts for attribute access
        vulnerability_findings = [
            f.model_dump() for f in aggregated_findings if f.type == "vulnerability"
        ]

        if vulnerability_findings:
            # Extract KEV and high EPSS vulnerabilities
            kev_vulns = []
            high_epss_vulns = []
            critical_vulns = []

            for finding in vulnerability_findings:
                details = finding.get("details", {})
                vulns = details.get("vulnerabilities", [details])

                for vuln in vulns:
                    vuln_info = {
                        "id": vuln.get("id", finding.get("id", "Unknown")),
                        "severity": vuln.get(
                            "severity", finding.get("severity", "UNKNOWN")
                        ),
                        "package": finding.get("component", "Unknown"),
                        "version": finding.get("version", ""),
                        "in_kev": vuln.get("in_kev", False),
                        "epss_score": vuln.get("epss_score"),
                        "kev_due_date": vuln.get("kev_due_date"),
                        "kev_ransomware_use": vuln.get("kev_ransomware_use", False),
                    }

                    if vuln.get("in_kev"):
                        kev_vulns.append(vuln_info)

                    if vuln.get("epss_score") and vuln.get("epss_score") >= 0.1:
                        high_epss_vulns.append(vuln_info)

                    if vuln.get("severity") in ["CRITICAL", "HIGH"] or vuln.get(
                        "in_kev"
                    ):
                        critical_vulns.append(vuln_info)

            # Send vulnerability_found notification if there are KEV, high EPSS, or critical/high vulns
            if kev_vulns or high_epss_vulns or critical_vulns:
                # Sort and get top 10 most critical vulnerabilities for email
                top_vulns = sorted(
                    critical_vulns,
                    key=lambda x: (
                        not x.get("in_kev", False),  # KEV first
                        -(x.get("epss_score") or 0),  # Then by EPSS
                        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                            x.get("severity", "LOW"), 4
                        ),
                    ),
                )[:10]

                subject = "[SECURITY ALERT] "
                if kev_vulns:
                    subject += f"{len(kev_vulns)} KEV Vulnerabilities in {project.name}"
                elif high_epss_vulns:
                    subject += f"High-Risk Vulnerabilities in {project.name}"
                else:
                    subject += f"Critical Vulnerabilities in {project.name}"

                message = f"Security scan detected critical vulnerabilities in {project.name}.\n\n"
                if kev_vulns:
                    message += f"[KEV] {len(kev_vulns)} Known Exploited Vulnerabilities (CISA KEV)\n"
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

                await notification_service.notify_project_members(
                    project=project,
                    event_type="vulnerability_found",
                    subject=subject,
                    message=message,
                    db=db,
                )

                logger.info(
                    f"Sent vulnerability_found notification for project {project.name}: "
                    f"{len(kev_vulns)} KEV, {len(high_epss_vulns)} high EPSS, {len(critical_vulns)} critical/high"
                )

                # Trigger vulnerability_found webhook
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
        logger.error(f"Failed to send notifications and trigger webhooks: {e}")
