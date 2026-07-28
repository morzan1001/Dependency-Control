"""Pydantic models for GitHub Actions OIDC token payloads (extra="ignore" discards unused claims)."""

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
