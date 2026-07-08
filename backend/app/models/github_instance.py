from datetime import datetime
from typing import Optional

from pydantic import ConfigDict, Field

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class GitHubInstance(MongoDocument, CreatedAtModel):
    """A configured GitHub instance (github.com or GitHub Enterprise Server)."""

    # Identity
    name: str = Field(..., description="Human-readable name (e.g. 'GitHub.com', 'GitHub Enterprise')")
    url: str = Field(..., description="OIDC issuer URL (e.g. 'https://token.actions.githubusercontent.com')")
    github_url: Optional[str] = Field(
        None,
        description="GitHub web URL (e.g. 'https://github.com'). Used for display/links.",
    )
    description: Optional[str] = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")

    # Authentication
    # oidc_audience is effectively required (enforced by API schemas and fail-closed
    # OIDC validation); stored Optional only so legacy documents still hydrate.
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens from this instance")
    access_token: Optional[str] = Field(
        None,
        exclude=True,
        description="Personal Access Token with 'repo' scope for GitHub API operations",
    )

    # Features
    auto_create_projects: bool = Field(
        False, description="Automatically create projects from OIDC tokens if they don't exist"
    )

    # Metadata
    created_by: str = Field(..., description="User ID of the admin who created this instance")
    last_modified_at: Optional[datetime] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)
