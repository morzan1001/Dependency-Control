"""External integrations for scan results (GitLab MR and GitHub PR comments)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Project, Scan
from app.models.stats import Stats
from app.services.github import GitHubService
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)


def _build_mr_comment(
    scan_id: str,
    stats: Stats,
    scan_url: str | None,
) -> str:
    """Build the MR comment body for scan results."""
    status_label = "[OK]"
    if stats.risk_score > 0:
        status_label = "[WARNING]"
    if stats.critical > 0 or stats.high > 0:
        status_label = "[ALERT]"

    marker = "<!-- dependency-control:scan-comment -->"
    scan_marker = f"<!-- dependency-control:scan-id:{scan_id} -->"

    comment_lines: list[str] = [
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
    scan_doc: Scan,
    project: Project,
    db: AsyncIOMotorDatabase,
) -> None:
    """Post a comment to the GitLab Merge Request with scan results."""
    if not project.gitlab_mr_comments_enabled:
        return
    if not project.gitlab_instance_id or not project.gitlab_project_id:
        logger.warning(f"Project {project.id} has MR comments enabled but missing GitLab instance/project ID")
        return
    if not scan_doc.commit_hash:
        return

    try:
        from app.repositories.gitlab_instances import GitLabInstanceRepository

        instance_repo = GitLabInstanceRepository(db)
        gitlab_instance = await instance_repo.get_by_id(project.gitlab_instance_id)

        if not gitlab_instance:
            logger.warning(f"GitLab instance {project.gitlab_instance_id} not found for project {project.id}")
            return

        if not gitlab_instance.is_active:
            logger.info(
                f"GitLab instance '{gitlab_instance.name}' is inactive, skipping MR decoration for project {project.id}"
            )
            return

        if not gitlab_instance.access_token:
            logger.info(
                f"GitLab instance '{gitlab_instance.name}' has no access token, skipping MR decoration for project {project.id}"
            )
            return

        gitlab_service = GitLabService(gitlab_instance)

        mrs = await gitlab_service.get_merge_requests_for_commit(project.gitlab_project_id, scan_doc.commit_hash)

        if not mrs:
            return

        relevant_mrs = [mr for mr in mrs if mr.state == "opened" and not mr.draft and not mr.work_in_progress]

        if not relevant_mrs:
            logger.info(f"No relevant open MRs for scan {scan_id} in project {project.id}")
            return

        from app.core.config import settings

        frontend_url = settings.FRONTEND_BASE_URL.rstrip("/")
        scan_url = f"{frontend_url}/projects/{project.id}/scans/{scan_id}"

        comment_body = _build_mr_comment(scan_id, stats, scan_url)
        marker = "<!-- dependency-control:scan-comment -->"

        for mr in relevant_mrs:
            try:
                await _update_or_create_mr_comment(
                    gitlab_service=gitlab_service,
                    gitlab_project_id=project.gitlab_project_id,
                    mr_iid=mr.iid,
                    comment_body=comment_body,
                    marker=marker,
                    project_id=str(project.id),
                    scan_id=scan_id,
                )
            except Exception as mr_err:
                logger.exception(
                    "Failed to decorate MR !%s for project %s, scan %s: %s",
                    mr.iid,
                    project.id,
                    scan_id,
                    mr_err,
                )

    except Exception as e:
        logger.exception(
            "Failed to decorate GitLab MR for project %s, scan %s: %s",
            project.id,
            scan_id,
            e,
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
    """Upsert an MR comment identified by `marker`."""
    existing_notes = await gitlab_service.get_merge_request_notes(gitlab_project_id, mr_iid)

    existing_comment_id: int | None = None
    existing_body: str | None = None

    for note in existing_notes:
        if marker in note.body:
            existing_comment_id = note.id
            existing_body = note.body
            break

    if existing_comment_id:
        if existing_body == comment_body:
            logger.info(f"MR comment already up to date for project {project_id}, MR !{mr_iid}, scan {scan_id}")
            return

        success = await gitlab_service.update_merge_request_comment(
            gitlab_project_id,
            mr_iid,
            existing_comment_id,
            comment_body,
        )
        if success:
            logger.info(f"Updated MR comment for project {project_id}, MR !{mr_iid}, scan {scan_id}")
        else:
            logger.warning(f"Failed to update MR comment for project {project_id}, MR !{mr_iid}, scan {scan_id}")
    else:
        success = await gitlab_service.post_merge_request_comment(gitlab_project_id, mr_iid, comment_body)
        if success:
            logger.info(f"Posted MR comment for project {project_id}, MR !{mr_iid}, scan {scan_id}")
        else:
            logger.warning(f"Failed to post MR comment for project {project_id}, MR !{mr_iid}, scan {scan_id}")


async def decorate_github_pr(
    scan_id: str,
    stats: Stats,
    scan_doc: Scan,
    project: Project,
    db: AsyncIOMotorDatabase,
) -> None:
    """Post a comment to the GitHub Pull Request with scan results."""
    if not project.github_pr_comments_enabled:
        return
    owner, _, repo = (project.github_repository_path or "").partition("/")
    if not project.github_instance_id or not owner or not repo:
        logger.warning(f"Project {project.id} has PR comments enabled but missing GitHub instance/repository path")
        return
    if not scan_doc.commit_hash:
        return

    try:
        from app.repositories.github_instances import GitHubInstanceRepository

        instance_repo = GitHubInstanceRepository(db)
        github_instance = await instance_repo.get_by_id(project.github_instance_id)

        if not github_instance:
            logger.warning(f"GitHub instance {project.github_instance_id} not found for project {project.id}")
            return

        if not github_instance.is_active:
            logger.info(
                f"GitHub instance '{github_instance.name}' is inactive, "
                f"skipping PR decoration for project {project.id}"
            )
            return

        if not github_instance.access_token:
            logger.info(
                f"GitHub instance '{github_instance.name}' has no access token, "
                f"skipping PR decoration for project {project.id}"
            )
            return

        github_service = GitHubService(github_instance)

        prs = await github_service.get_pull_requests_for_commit(owner, repo, scan_doc.commit_hash)

        if not prs:
            return

        relevant_prs = [pr for pr in prs if pr.state == "open" and pr.draft is False]

        if not relevant_prs:
            logger.info(f"No relevant open PRs for scan {scan_id} in project {project.id}")
            return

        from app.core.config import settings

        frontend_url = settings.FRONTEND_BASE_URL.rstrip("/")
        scan_url = f"{frontend_url}/projects/{project.id}/scans/{scan_id}"

        comment_body = _build_mr_comment(scan_id, stats, scan_url)
        marker = "<!-- dependency-control:scan-comment -->"

        for pr in relevant_prs:
            try:
                await _update_or_create_pr_comment(
                    github_service=github_service,
                    owner=owner,
                    repo=repo,
                    pr_number=pr.number,
                    comment_body=comment_body,
                    marker=marker,
                    project_id=str(project.id),
                    scan_id=scan_id,
                )
            except Exception as pr_err:
                logger.exception(
                    "Failed to decorate PR #%s for project %s, scan %s: %s",
                    pr.number,
                    project.id,
                    scan_id,
                    pr_err,
                )

    except Exception as e:
        logger.exception(
            "Failed to decorate GitHub PR for project %s, scan %s: %s",
            project.id,
            scan_id,
            e,
        )


async def _update_or_create_pr_comment(
    github_service: GitHubService,
    owner: str,
    repo: str,
    pr_number: int,
    comment_body: str,
    marker: str,
    project_id: str,
    scan_id: str,
) -> None:
    """Upsert a PR comment identified by `marker`."""
    existing_comments = await github_service.get_pull_request_comments(owner, repo, pr_number)

    existing_comment_id: int | None = None
    existing_body: str | None = None

    for comment in existing_comments:
        if marker in (comment.body or ""):
            existing_comment_id = comment.id
            existing_body = comment.body
            break

    if existing_comment_id is not None:
        if existing_body == comment_body:
            logger.info(f"PR comment already up to date for project {project_id}, PR #{pr_number}, scan {scan_id}")
            return

        success = await github_service.update_pull_request_comment(owner, repo, existing_comment_id, comment_body)
        if success:
            logger.info(f"Updated PR comment for project {project_id}, PR #{pr_number}, scan {scan_id}")
        else:
            logger.warning(f"Failed to update PR comment for project {project_id}, PR #{pr_number}, scan {scan_id}")
    else:
        success = await github_service.post_pull_request_comment(owner, repo, pr_number, comment_body)
        if success:
            logger.info(f"Posted PR comment for project {project_id}, PR #{pr_number}, scan {scan_id}")
        else:
            logger.warning(f"Failed to post PR comment for project {project_id}, PR #{pr_number}, scan {scan_id}")
