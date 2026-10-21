import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from functools import partial
from typing import Any

from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.gitlab_instances import GitLabInstanceRepository
from app.repositories.scans import ScanRepository
from app.services.github import GitHubService, split_repo_path
from app.services.gitlab import GitLabService

logger = logging.getLogger(__name__)

_VcsRepo = tuple[Callable[[], Awaitable[list[str] | None]], Callable[[], Awaitable[str | None]]]


async def _vcs_repo(project: dict[str, Any], db: Any) -> _VcsRepo | None:
    gitlab_project_id = project.get("gitlab_project_id")
    if project.get("gitlab_instance_id") and gitlab_project_id:
        gitlab = await GitLabInstanceRepository(db).get_usable(project["gitlab_instance_id"])
        if not gitlab:
            return None
        gitlab_service = GitLabService(gitlab)
        return (
            partial(gitlab_service.list_branches, gitlab_project_id),
            partial(gitlab_service.get_default_branch, gitlab_project_id),
        )
    repo = split_repo_path(project.get("github_repository_path"))
    if project.get("github_instance_id") and repo:
        github = await GitHubInstanceRepository(db).get_usable(project["github_instance_id"])
        if not github:
            return None
        github_service = GitHubService(github)
        return partial(github_service.list_branches, *repo), partial(github_service.get_default_branch, *repo)
    return None


async def sync_project_branches(project: dict[str, Any], db: Any) -> bool | None:
    """None without a usable VCS instance, False when the VCS failed or listed no branches; both leave the project."""
    vcs = await _vcs_repo(project, db)
    if not vcs:
        return None
    list_branches, fetch_default_branch = vcs
    vcs_branches = await list_branches()
    if not vcs_branches:
        return False

    project_id = project["_id"]
    vcs_set = set(vcs_branches)
    # The tag-build check has to fetch documents, so it runs only on the few branches the VCS lacks.
    candidates = [b for b in await db.scans.distinct("branch", {"project_id": project_id}) if b not in vcs_set]
    deleted = sorted(await ScanRepository(db).branch_names(project_id, candidates))

    update_fields: dict[str, Any] = {"deleted_branches": deleted, "branches_checked_at": datetime.now(timezone.utc)}
    stored_default = project.get("default_branch")
    # A default the VCS lacks was renamed or retired, so it cannot be a deliberate choice either.
    if stored_default not in vcs_set:
        vcs_default = await fetch_default_branch()
        if vcs_default and vcs_default != stored_default:
            update_fields["default_branch"] = vcs_default

    await db.projects.update_one({"_id": project_id}, {"$set": update_fields})
    await ScanRepository(db).sync_project_head(project_id)
    if deleted:
        logger.info("Project %s: %d deleted branch(es) detected", project.get("name", project_id), len(deleted))
    return True
