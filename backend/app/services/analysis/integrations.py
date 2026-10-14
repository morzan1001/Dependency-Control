"""The scan result as a comment on the merge and pull requests of the scanned commit."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from functools import partial
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from motor.motor_asyncio import AsyncIOMotorDatabase

    from app.models.github_instance import GitHubInstance
    from app.models.gitlab_instance import GitLabInstance

from app.core.config import scan_link
from app.core.constants import SCAN_STATUS_COMPLETED, ScanStatus
from app.models.project import Project, Scan
from app.models.stats import Stats
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
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


class _Review(NamedTuple):
    """An open merge or pull request whose head is the scanned commit, and the calls on its comments."""

    label: str
    comments_by: Callable[[int], Awaitable[list[tuple[int, str]] | None]]
    update: Callable[[int, str], Awaitable[bool]]
    post: Callable[[str], Awaitable[bool]]


class _Site(NamedTuple):
    """A provider a project comments its scans on, and how its open reviews of a commit are read."""

    provider: str
    instance_id: str
    instances: type[GitLabInstanceRepository] | type[GitHubInstanceRepository]
    reviews: Callable[[Any, str], Awaitable[tuple[GitLabService | GitHubService, list[_Review]]]]


async def _merge_requests(
    instance: GitLabInstance, commit: str, *, project_id: int
) -> tuple[GitLabService, list[_Review]]:
    service = GitLabService(instance)

    async def notes_by(iid: int, author: int) -> list[tuple[int, str]] | None:
        notes = await service.get_merge_request_notes(project_id, iid)
        # GitLab lists notes newest first.
        return None if notes is None else [(note.id, note.body) for note in reversed(notes) if note.author_id == author]

    mrs = await service.get_merge_requests_for_commit(project_id, commit)
    return service, [
        _Review(
            f"MR !{mr.iid}",
            partial(notes_by, mr.iid),
            partial(service.update_merge_request_comment, project_id, mr.iid),
            partial(service.post_merge_request_comment, project_id, mr.iid),
        )
        for mr in mrs
        if mr.state == "opened" and not mr.draft and not mr.work_in_progress and mr.sha == commit
    ]


async def _pull_requests(
    instance: GitHubInstance, commit: str, *, repo: tuple[str, str], branch: str
) -> tuple[GitHubService, list[_Review]]:
    service = GitHubService(instance)
    owner, name = repo

    async def comments_by(number: int, author: int) -> list[tuple[int, str]] | None:
        comments = await service.get_pull_request_comments(owner, name, number)
        return None if comments is None else [(c.id, c.body or "") for c in comments if c.user_id == author]

    head_sha, prs = await service.get_pull_requests_for_commit(owner, name, commit, branch)
    return service, [
        _Review(
            f"PR #{pr.number}",
            partial(comments_by, pr.number),
            partial(service.update_pull_request_comment, owner, name),
            partial(service.post_pull_request_comment, owner, name, pr.number),
        )
        for pr in prs
        if pr.state == "open" and pr.draft is False and pr.head_sha == head_sha
    ]


def _sites(project: Project, scan: Scan) -> list[_Site]:
    """The providers this project has scan comments on for, warning about one it has no link to."""
    sites = []
    if project.gitlab_mr_comments_enabled:
        if project.gitlab_instance_id and project.gitlab_project_id:
            merge_requests = partial(_merge_requests, project_id=project.gitlab_project_id)
            sites.append(_Site("GitLab", project.gitlab_instance_id, GitLabInstanceRepository, merge_requests))
        else:
            logger.warning("Project %s has MR comments enabled but missing GitLab instance/project ID", project.id)
    if project.github_pr_comments_enabled:
        repo = split_repo_path(project.github_repository_path)
        if project.github_instance_id and repo:
            pull_requests = partial(_pull_requests, repo=repo, branch=scan.branch)
            sites.append(_Site("GitHub", project.github_instance_id, GitHubInstanceRepository, pull_requests))
        else:
            logger.warning("Project %s has PR comments enabled but missing GitHub instance/repository path", project.id)
    return sites


async def _upsert_scan_comment(review: _Review, author: int, body: str, label: str) -> None:
    """Edit the first marked comment (the bot's own, oldest first) or post one; an unread list (None) posts no second."""
    comments = await review.comments_by(author)
    if comments is None:
        logger.warning("Scan comment on %s skipped: its comments could not be read", label)
        return
    existing = next(((cid, text) for cid, text in comments if _SCAN_COMMENT_MARKER in text), None)
    if existing is None:
        action, success = "post", await review.post(body)
    elif existing[1] == body:
        logger.info("Scan comment on %s is already up to date", label)
        return
    else:
        action, success = "update", await review.update(existing[0], body)

    if success:
        logger.info("Scan comment on %s: %s done", label, action)
    else:
        logger.warning("Scan comment on %s: %s failed", label, action)


async def _decorate(
    site: _Site, commit: str, body: str, project: Project, scan_id: str, db: AsyncIOMotorDatabase
) -> None:
    instance = await site.instances(db).get_usable(site.instance_id)
    if not instance:
        logger.warning(
            "%s instance %s is missing, inactive or has no token; skipping review decoration for project %s",
            site.provider,
            site.instance_id,
            project.id,
        )
        return

    service, reviews = await site.reviews(instance, commit)
    if not reviews:
        logger.info("No open %s review has scan %s's commit as head in project %s", site.provider, scan_id, project.id)
        return

    bot_id = await service.get_current_user_id()
    if bot_id is None:
        logger.warning("%s token user unresolved; skipping review decoration for project %s", site.provider, project.id)
        return

    for review in reviews:
        label = f"{review.label} of project {project.id}"
        try:
            await _upsert_scan_comment(review, bot_id, body, label)
        except Exception:
            logger.exception("Failed to decorate %s, scan %s", label, scan_id)


async def decorate_reviews(
    scan_id: str,
    stats: Stats,
    status: ScanStatus,
    error: str | None,
    scan_doc: Scan,
    project: Project,
    db: AsyncIOMotorDatabase,
) -> None:
    """Comment the scan result on the open merge and pull requests whose head is the scanned commit."""
    sites = _sites(project, scan_doc)
    commit = scan_doc.commit_hash
    if not commit:
        return
    body = _build_scan_comment(stats, scan_link(str(project.id), scan_id), status, error)
    for site in sites:
        try:
            await _decorate(site, commit, body, project, scan_id, db)
        except Exception:
            logger.exception(
                "Failed to decorate %s reviews for project %s, scan %s", site.provider, project.id, scan_id
            )
