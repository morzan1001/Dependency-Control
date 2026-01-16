import logging
from typing import Any, Dict

from app.models.project import Project
from app.models.stats import Stats
from app.models.system import SystemSettings
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)


async def decorate_gitlab_mr(
    scan_id: str,
    stats: Stats,
    scan_doc: Dict[str, Any],
    project: Project,
    system_settings: Dict[str, Any],
):
    """
    Post a comment to the GitLab Merge Request with scan results.
    """
    if not (
        project.gitlab_mr_comments_enabled
        and project.gitlab_project_id
        and scan_doc.get("commit_hash")
    ):
        return

    try:
        settings_obj = SystemSettings(**system_settings)
        gitlab_service = GitLabService(settings_obj)

        mrs = await gitlab_service.get_merge_requests_for_commit(
            project.gitlab_project_id, scan_doc["commit_hash"]
        )

        if mrs:
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

            dashboard_url = getattr(settings_obj, "dashboard_url", None)
            if not dashboard_url:
                logger.warning(
                    f"Dashboard URL not configured; MR comment will omit links for project {project.id}, scan {scan_id}"
                )
            scan_url = (
                f"{dashboard_url}/projects/{project.id}/scans/{scan_id}"
                if dashboard_url
                else None
            )

            status_label = "[OK]"
            if stats.risk_score > 0:
                status_label = "[WARNING]"
            if stats.critical > 0 or stats.high > 0:
                status_label = "[ALERT]"

            marker = "<!-- dependency-control:scan-comment -->"
            scan_marker = f"<!-- dependency-control:scan-id:{scan_id} -->"

            comment_body = f"""
{marker}
{scan_marker}
### {status_label} Dependency Control Scan Results

**Status:** Completed
**Risk Score:** {stats.risk_score}

| Severity | Count |
| :--- | :--- |
| Critical | {stats.critical} |
| High | {stats.high} |
| Medium | {stats.medium} |
| Low | {stats.low} |
"""

            if scan_url:
                comment_body += f"\n[View Full Report]({scan_url})\n"

            for mr in relevant_mrs:
                try:
                    existing_notes = await gitlab_service.get_merge_request_notes(
                        project.gitlab_project_id, mr["iid"]
                    )

                    existing_comment_id = None
                    existing_body = None
                    for note in existing_notes:
                        body = note.get("body", "")
                        if marker in body:
                            existing_comment_id = note.get("id")
                            existing_body = body
                            break

                    if existing_comment_id:
                        if existing_body == comment_body:
                            logger.info(
                                f"MR comment already up to date for project {project.id}, MR !{mr['iid']}, scan {scan_id}"
                            )
                            continue

                        await gitlab_service.update_merge_request_comment(
                            project.gitlab_project_id,
                            mr["iid"],
                            existing_comment_id,
                            comment_body,
                        )
                        logger.info(
                            f"Updated MR comment for project {project.id}, MR !{mr['iid']}, scan {scan_id}"
                        )
                    else:
                        await gitlab_service.post_merge_request_comment(
                            project.gitlab_project_id, mr["iid"], comment_body
                        )
                        logger.info(
                            f"Posted MR comment for project {project.id}, MR !{mr['iid']}, scan {scan_id}"
                        )
                except Exception as mr_err:
                    logger.error(
                        f"Failed to decorate MR !{mr.get('iid')} for project {project.id}, scan {scan_id}: {mr_err}"
                    )

    except Exception as e:
        logger.error(
            f"Failed to decorate GitLab MR for project {project.id}, scan {scan_id}: {e}"
        )
