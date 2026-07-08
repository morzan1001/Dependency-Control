"""Pydantic models for GitHub Actions OIDC token payloads (extra="ignore" discards unused claims)."""

from typing import Optional

from pydantic import BaseModel, ConfigDict


class GitHubOIDCPayload(BaseModel):
    """Validated OIDC JWT token payload from GitHub Actions."""

    model_config = ConfigDict(extra="ignore")

    repository_id: str
    repository: str  # "owner/repo" format
    repository_owner: str
    actor: str  # Username who triggered the workflow
    ref: Optional[str] = None
    sha: Optional[str] = None
    workflow: Optional[str] = None
    run_id: Optional[str] = None
    event_name: Optional[str] = None
