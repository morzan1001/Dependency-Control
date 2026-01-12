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
        # Ensure we have a valid SystemSettings object
        settings_obj = SystemSettings(**system_settings)
        gitlab_service = GitLabService(settings_obj)

        mrs = await gitlab_service.get_merge_requests_for_commit(
            project.gitlab_project_id, scan_doc["commit_hash"]
        )

        if mrs:
            # Construct Markdown Comment
            # Use dashboard_url from settings if available, otherwise try to infer or use a placeholder
            dashboard_url = getattr(
                settings_obj, "dashboard_url", "http://localhost:5173"
            )
            scan_url = f"{dashboard_url}/projects/{project.id}/scans/{scan_id}"

            status_label = "[OK]"
            if stats.risk_score > 0:
                status_label = "[WARNING]"
            if stats.critical > 0 or stats.high > 0:
                status_label = "[ALERT]"

            comment_body = f"""
### {status_label} Dependency Control Scan Results

**Status:** Completed
**Risk Score:** {stats.risk_score}

| Severity | Count |
| :--- | :--- |
| Critical | {stats.critical} |
| High | {stats.high} |
| Medium | {stats.medium} |
| Low | {stats.low} |

[View Full Report]({scan_url})
"""
            for mr in mrs:
                # Check for existing comment to update instead of creating a new one (deduplication)
                existing_notes = await gitlab_service.get_merge_request_notes(
                    project.gitlab_project_id, mr["iid"]
                )

                existing_comment_id = None
                for note in existing_notes:
                    if "Dependency Control Scan Results" in note.get("body", ""):
                        existing_comment_id = note["id"]
                        break

                if existing_comment_id:
                    await gitlab_service.update_merge_request_comment(
                        project.gitlab_project_id,
                        mr["iid"],
                        existing_comment_id,
                        comment_body,
                    )
                    logger.info(
                        f"Updated scan results on MR !{mr['iid']} for project {project.name}"
                    )
                else:
                    await gitlab_service.post_merge_request_comment(
                        project.gitlab_project_id, mr["iid"], comment_body
                    )
                    logger.info(
                        f"Posted scan results to MR !{mr['iid']} for project {project.name}"
                    )

    except Exception as e:
        logger.error(f"Failed to decorate GitLab MR: {e}")
