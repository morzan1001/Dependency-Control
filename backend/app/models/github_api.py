"""Pydantic models for GitHub API responses and Actions OIDC token payloads (extra="ignore" discards unused fields)."""

from pydantic import BaseModel, ConfigDict


class GitHubOIDCPayload(BaseModel):
    """Validated OIDC JWT token payload from GitHub Actions."""

    model_config = ConfigDict(extra="ignore")

    repository_id: str
    repository: str  # "owner/repo" format
    repository_owner: str
    actor: str  # Username who triggered the workflow
    ref: str | None = None
    sha: str | None = None
    workflow: str | None = None
    run_id: str | None = None
    event_name: str | None = None


class GitHubPullRequest(BaseModel):
    """Pull request from GET /repos/{owner}/{repo}/commits/{sha}/pulls."""

    model_config = ConfigDict(extra="ignore")

    number: int
    state: str
    draft: bool = False


class GitHubIssueComment(BaseModel):
    """Comment from GET /repos/{owner}/{repo}/issues/{number}/comments."""

    model_config = ConfigDict(extra="ignore")

    id: int
    # GitHub's issue-comment schema declares `body` optional.
    body: str | None = None
