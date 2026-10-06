"""External integrations for scan results (GitLab MR and GitHub PR comments)."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from functools import partial
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import scan_link
from app.core.constants import SCAN_STATUS_COMPLETED, ScanStatus
from app.models.project import Project, Scan
from app.models.stats import Stats
from app.services.github import GitHubService, split_repo_path
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)

# Identifies our own comment on an MR/PR so repeat scans update it instead of appending a duplicate.
_SCAN_COMMENT_MARKER = "<!-- dependency-control:scan-comment -->"


def _build_scan_comment(stats: Stats, scan_url: str, status: ScanStatus, error: str | None) -> str:
    status_label = "[OK]"
    if stats.risk_score > 0 or status != SCAN_STATUS_COMPLETED:
        status_label = "[WARNING]"
    if stats.critical > 0 or stats.high > 0:
        status_label = "[ALERT]"
    status_text = "Completed" if status == SCAN_STATUS_COMPLETED else f"Completed with errors: {error}"

    return "\n".join(
        [
            _SCAN_COMMENT_MARKER,
            f"### {status_label} Dependency Control Scan Results",
            "",
            f"**Status:** {status_text}",
            f"**Risk Score:** {stats.risk_score}",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| Critical | {stats.critical} |",
            f"| High | {stats.high} |",
            f"| Medium | {stats.medium} |",
            f"| Low | {stats.low} |",
            "",
            f"[View Full Report]({scan_url})",
        ]
    )


async def _upsert_scan_comment(
    comments: list[tuple[int, str]] | None,
    body: str,
    update: Callable[[int, str], Awaitable[bool]],
    post: Callable[[str], Awaitable[bool]],
    label: str,
) -> None:
    """Edit the first marked comment (the bot's own, oldest first) or post one; an unread list (None) posts no second."""
    if comments is None:
        logger.warning("Scan comment on %s skipped: its comments could not be read", label)
        return
    existing = next(((cid, text) for cid, text in comments if _SCAN_COMMENT_MARKER in text), None)
    if existing is None:
        action, success = "post", await post(body)
    elif existing[1] == body:
        logger.info("Scan comment on %s is already up to date", label)
        return
    else:
        action, success = "update", await update(existing[0], body)

    if success:
        logger.info("Scan comment on %s: %s done", label, action)
    else:
        logger.warning("Scan comment on %s: %s failed", label, action)


async def decorate_gitlab_mr(
    scan_id: str,
    stats: Stats,
    status: ScanStatus,
    error: str | None,
    scan_doc: Scan,
    project: Project,
    db: AsyncIOMotorDatabase,
) -> None:
    """Comment the scan result on the open GitLab merge requests whose head is the scanned commit."""
    if not project.gitlab_mr_comments_enabled:
        return
    if not project.gitlab_instance_id or not project.gitlab_project_id:
        logger.warning(f"Project {project.id} has MR comments enabled but missing GitLab instance/project ID")
        return
    if not scan_doc.commit_hash:
        return

    try:
        from app.repositories.gitlab_instances import GitLabInstanceRepository

        gitlab_instance = await GitLabInstanceRepository(db).get_usable(project.gitlab_instance_id)
        if not gitlab_instance:
            logger.warning(
                "GitLab instance %s is missing, inactive or has no token; skipping MR decoration for project %s",
                project.gitlab_instance_id,
                project.id,
            )
            return

        gitlab_service = GitLabService(gitlab_instance)
        gitlab_project_id = project.gitlab_project_id
        mrs = await gitlab_service.get_merge_requests_for_commit(gitlab_project_id, scan_doc.commit_hash)
        relevant_mrs = [
            mr
            for mr in mrs
            if mr.state == "opened" and not mr.draft and not mr.work_in_progress and mr.sha == scan_doc.commit_hash
        ]
        if not relevant_mrs:
            logger.info(f"No open MR has scan {scan_id}'s commit as head in project {project.id}")
            return

        bot_id = await gitlab_service.get_current_user_id()
        if bot_id is None:
            logger.warning("GitLab token user unresolved; skipping MR decoration for project %s", project.id)
            return

        body = _build_scan_comment(stats, scan_link(str(project.id), scan_id), status, error)
        for mr in relevant_mrs:
            try:
                notes = await gitlab_service.get_merge_request_notes(gitlab_project_id, mr.iid)
                # GitLab lists notes newest first.
                own = None if notes is None else [(n.id, n.body) for n in reversed(notes) if n.author_id == bot_id]
                await _upsert_scan_comment(
                    own,
                    body,
                    partial(gitlab_service.update_merge_request_comment, gitlab_project_id, mr.iid),
                    partial(gitlab_service.post_merge_request_comment, gitlab_project_id, mr.iid),
                    f"MR !{mr.iid} of project {project.id}",
                )
            except Exception:
                logger.exception("Failed to decorate MR !%s for project %s, scan %s", mr.iid, project.id, scan_id)

    except Exception:
        logger.exception("Failed to decorate GitLab MR for project %s, scan %s", project.id, scan_id)


async def decorate_github_pr(
    scan_id: str,
    stats: Stats,
    status: ScanStatus,
    error: str | None,
    scan_doc: Scan,
    project: Project,
    db: AsyncIOMotorDatabase,
) -> None:
    """Comment the scan result on the open GitHub pull requests whose head is the scanned commit."""
    if not project.github_pr_comments_enabled:
        return
    repo_path = split_repo_path(project.github_repository_path)
    if not project.github_instance_id or not repo_path:
        logger.warning(f"Project {project.id} has PR comments enabled but missing GitHub instance/repository path")
        return
    if not scan_doc.commit_hash:
        return

    try:
        from app.repositories.github_instances import GitHubInstanceRepository

        github_instance = await GitHubInstanceRepository(db).get_usable(project.github_instance_id)
        if not github_instance:
            logger.warning(
                "GitHub instance %s is missing, inactive or has no token; skipping PR decoration for project %s",
                project.github_instance_id,
                project.id,
            )
            return

        owner, repo = repo_path
        github_service = GitHubService(github_instance)
        head_sha, prs = await github_service.get_pull_requests_for_commit(owner, repo, scan_doc.commit_hash)
        # A head found through a merge commit's parent is a PR's only in that PR's own pull_request
        # build, whose branch (GITHUB_REF_NAME) is "<number>/merge"; a pushed branch merge is not.
        relevant_prs = [
            pr
            for pr in prs
            if pr.state == "open"
            and pr.draft is False
            and pr.head_sha == head_sha
            and (head_sha == scan_doc.commit_hash or scan_doc.branch == f"{pr.number}/merge")
        ]
        if not relevant_prs:
            logger.info(f"No open PR has scan {scan_id}'s commit as head in project {project.id}")
            return

        bot_id = await github_service.get_current_user_id()
        if bot_id is None:
            logger.warning("GitHub token user unresolved; skipping PR decoration for project %s", project.id)
            return

        body = _build_scan_comment(stats, scan_link(str(project.id), scan_id), status, error)
        for pr in relevant_prs:
            try:
                comments = await github_service.get_pull_request_comments(owner, repo, pr.number)
                own = None if comments is None else [(c.id, c.body or "") for c in comments if c.user_id == bot_id]
                await _upsert_scan_comment(
                    own,
                    body,
                    partial(github_service.update_pull_request_comment, owner, repo),
                    partial(github_service.post_pull_request_comment, owner, repo, pr.number),
                    f"PR #{pr.number} of project {project.id}",
                )
            except Exception:
                logger.exception("Failed to decorate PR #%s for project %s, scan %s", pr.number, project.id, scan_id)

    except Exception:
        logger.exception("Failed to decorate GitHub PR for project %s, scan %s", project.id, scan_id)
