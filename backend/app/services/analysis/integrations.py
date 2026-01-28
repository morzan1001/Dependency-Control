"""
External integrations for scan results.

Handles posting scan results to GitLab MRs and other external services.
"""

import logging
from typing import List, Optional

from app.models.project import Project
from app.models.stats import Stats
from app.models.system import SystemSettings
from app.services.gitlab import GitLabService
from app.services.analysis.types import ScanDict, SystemSettingsDict

logger = logging.getLogger(__name__)


def _build_mr_comment(
    scan_id: str,
    stats: Stats,
    scan_url: Optional[str],
) -> str:
    """
    Build the MR comment body for scan results.

    Args:
        scan_id: The scan ID
        stats: The scan statistics
        scan_url: Optional URL to the scan report

    Returns:
        The formatted comment body
    """
    # Determine status label based on findings
    status_label = "[OK]"
    if stats.risk_score > 0:
        status_label = "[WARNING]"
    if stats.critical > 0 or stats.high > 0:
        status_label = "[ALERT]"

    marker = "<!-- dependency-control:scan-comment -->"
    scan_marker = f"<!-- dependency-control:scan-id:{scan_id} -->"

    comment_lines: List[str] = [
        marker,
        scan_marker,
        f"### {status_label} Dependency Control Scan Results",
        "",
        "**Status:** Completed",
        f"**Risk Score:** {stats.risk_score}",
        "",
        "| Severity | Count |",
        "| :--- | :--- |",
        f"| Critical | {stats.critical} |",
        f"| High | {stats.high} |",
        f"| Medium | {stats.medium} |",
        f"| Low | {stats.low} |",
    ]

    if scan_url:
        comment_lines.append("")
        comment_lines.append(f"[View Full Report]({scan_url})")

    return "\n".join(comment_lines)


async def decorate_gitlab_mr(
    scan_id: str,
    stats: Stats,
    scan_doc: ScanDict,
    project: Project,
    system_settings: SystemSettingsDict,
) -> None:
    """
    Post a comment to the GitLab Merge Request with scan results.

    Args:
        scan_id: The scan ID
        stats: The scan statistics
        scan_doc: The scan document from the database
        project: The project model
        system_settings: System settings dict containing GitLab config
    """
    # Check preconditions
    if not project.gitlab_mr_comments_enabled:
        return
    if not project.gitlab_project_id:
        return
    if not scan_doc.get("commit_hash"):
        return

    try:
        settings_obj = SystemSettings(**system_settings)
        gitlab_service = GitLabService(settings_obj)

        # Find MRs for this commit
        mrs = await gitlab_service.get_merge_requests_for_commit(
            project.gitlab_project_id, scan_doc["commit_hash"]
        )

        if not mrs:
            return

        # Filter to only open, non-draft MRs
        relevant_mrs = [
            mr
            for mr in mrs
            if mr.get("state") == "opened"
            and not mr.get("draft")
            and not mr.get("work_in_progress")
        ]

        if not relevant_mrs:
            logger.info(
                f"No relevant open MRs for scan {scan_id} in project {project.id}"
            )
            return

        # Build scan URL
        dashboard_url = getattr(settings_obj, "dashboard_url", None)
        if not dashboard_url:
            logger.warning(
                f"Dashboard URL not configured; MR comment will omit links "
                f"for project {project.id}, scan {scan_id}"
            )
        scan_url = (
            f"{dashboard_url}/projects/{project.id}/scans/{scan_id}"
            if dashboard_url
            else None
        )

        # Build comment
        comment_body = _build_mr_comment(scan_id, stats, scan_url)
        marker = "<!-- dependency-control:scan-comment -->"

        # Post or update comment on each relevant MR
        for mr in relevant_mrs:
            try:
                await _update_or_create_mr_comment(
                    gitlab_service=gitlab_service,
                    gitlab_project_id=project.gitlab_project_id,
                    mr_iid=mr["iid"],
                    comment_body=comment_body,
                    marker=marker,
                    project_id=str(project.id),
                    scan_id=scan_id,
                )
            except Exception as mr_err:
                logger.error(
                    f"Failed to decorate MR !{mr.get('iid')} for project "
                    f"{project.id}, scan {scan_id}: {mr_err}"
                )

    except Exception as e:
        logger.error(
            f"Failed to decorate GitLab MR for project {project.id}, scan {scan_id}: {e}"
        )


async def _update_or_create_mr_comment(
    gitlab_service: GitLabService,
    gitlab_project_id: int,
    mr_iid: int,
    comment_body: str,
    marker: str,
    project_id: str,
    scan_id: str,
) -> None:
    """
    Update an existing MR comment or create a new one.

    Args:
        gitlab_service: The GitLab service instance
        gitlab_project_id: The GitLab project ID
        mr_iid: The MR internal ID
        comment_body: The comment body to post
        marker: The marker to identify our comments
        project_id: The project ID (for logging)
        scan_id: The scan ID (for logging)
    """
    existing_notes = await gitlab_service.get_merge_request_notes(
        gitlab_project_id, mr_iid
    )

    # Find existing comment
    existing_comment_id: Optional[int] = None
    existing_body: Optional[str] = None

    for note in existing_notes:
        body = note.get("body", "")
        if marker in body:
            existing_comment_id = note.get("id")
            existing_body = body
            break

    if existing_comment_id:
        # Check if update is needed
        if existing_body == comment_body:
            logger.info(
                f"MR comment already up to date for project {project_id}, "
                f"MR !{mr_iid}, scan {scan_id}"
            )
            return

        # Update existing comment
        success = await gitlab_service.update_merge_request_comment(
            gitlab_project_id,
            mr_iid,
            existing_comment_id,
            comment_body,
        )
        if success:
            logger.info(
                f"Updated MR comment for project {project_id}, MR !{mr_iid}, scan {scan_id}"
            )
        else:
            logger.warning(
                f"Failed to update MR comment for project {project_id}, "
                f"MR !{mr_iid}, scan {scan_id}"
            )
    else:
        # Create new comment
        success = await gitlab_service.post_merge_request_comment(
            gitlab_project_id, mr_iid, comment_body
        )
        if success:
            logger.info(
                f"Posted MR comment for project {project_id}, MR !{mr_iid}, scan {scan_id}"
            )
        else:
            logger.warning(
                f"Failed to post MR comment for project {project_id}, "
                f"MR !{mr_iid}, scan {scan_id}"
            )
