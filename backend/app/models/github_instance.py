from datetime import datetime

from pydantic import ConfigDict, Field

from app.models.base import CreatedAtModel, VcsInstanceModel
from app.models.types import MongoDocument

GITHUB_SHARED_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def is_shared_github_issuer(url: str) -> bool:
    """Whether ``url`` is the issuer every github.com repository's tokens carry, not an enterprise-scoped one."""
    return url.rstrip("/") == GITHUB_SHARED_OIDC_ISSUER


class GitHubInstance(MongoDocument, CreatedAtModel, VcsInstanceModel):
    """A configured GitHub instance (github.com or GitHub Enterprise Server)."""

    # Identity
    name: str = Field(..., description="Human-readable name (e.g. 'GitHub.com', 'GitHub Enterprise')")
    url: str = Field(..., description="OIDC issuer URL (e.g. 'https://token.actions.githubusercontent.com')")
    github_url: str | None = Field(
        None,
        description="GitHub web URL (e.g. 'https://github.com'). Used for display/links.",
    )
    description: str | None = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")

    # Authentication
    # oidc_audience is effectively required (enforced by API schemas and fail-closed
    # OIDC validation); stored Optional only so legacy documents still hydrate.
    oidc_audience: str | None = Field(None, description="Expected 'aud' claim for OIDC tokens from this instance")
    access_token: str | None = Field(
        None,
        exclude=True,
        description="Personal Access Token for GitHub API operations. Classic PAT: 'repo', plus "
        "'read:org' when sync_teams is on. The token's identity must be a member of the "
        "organisation, or it sees only a subset of teams and members.",
    )
    allowed_owner_ids: list[str] = Field(
        default_factory=list,
        description="Numeric repository_owner_id claims whose tokens are accepted; empty accepts every owner",
    )

    # Features
    auto_create_projects: bool = Field(
        False, description="Automatically create projects from OIDC tokens if they don't exist"
    )
    sync_teams: bool = Field(False, description="Sync GitHub team members to local teams")

    # Metadata
    created_by: str = Field(..., description="User ID of the admin who created this instance")
    last_modified_at: datetime | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def is_shared_issuer(self) -> bool:
        return is_shared_github_issuer(self.url)

    def accepts_owner(self, owner_id: str | None) -> bool:
        return not self.allowed_owner_ids or owner_id in self.allowed_owner_ids
