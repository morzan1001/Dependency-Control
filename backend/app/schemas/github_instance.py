from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas._oidc_audience import (
    validate_audience_not_blank,
    validate_optional_audience_not_blank,
)


class GitHubInstanceBase(BaseModel):
    """Base schema for GitHub instance.

    The oidc_audience field and its blank-check live on the Create/Update
    schemas, not here, so the Response schema can serialize instances whose
    audience is null.
    """

    name: str = Field(..., description="Human-readable name (e.g. 'GitHub.com', 'GitHub Enterprise')")
    url: str = Field(..., description="OIDC issuer URL (e.g. 'https://token.actions.githubusercontent.com')")
    github_url: str | None = Field(None, description="GitHub web URL (e.g. 'https://github.com')")
    description: str | None = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")
    auto_create_projects: bool = Field(False, description="Automatically create projects from OIDC tokens")
    sync_teams: bool = Field(False, description="Sync GitHub team members to local teams")


class GitHubInstanceCreate(GitHubInstanceBase):
    """Schema for creating a new GitHub instance."""

    oidc_audience: str = Field(
        ...,
        min_length=1,
        description="REQUIRED expected 'aud' claim for OIDC tokens. "
        "Must match the GitHub Actions token request 'audience'.",
    )
    access_token: str | None = Field(None, description="Personal Access Token for GitHub API operations")

    _audience_not_blank = field_validator("oidc_audience")(validate_audience_not_blank)

    @model_validator(mode="after")
    def validate_token_dependent_features(self) -> "GitHubInstanceCreate":
        if self.sync_teams and not self.access_token:
            raise ValueError("An access token is required to enable team syncing")
        return self


class GitHubInstanceUpdate(BaseModel):
    """Schema for updating a GitHub instance. All fields optional."""

    name: str | None = Field(None, description="Human-readable name")
    url: str | None = Field(None, description="OIDC issuer URL")
    github_url: str | None = Field(None, description="GitHub web URL")
    description: str | None = Field(None, description="Optional description")
    is_active: bool | None = Field(None, description="Whether this instance is active")
    oidc_audience: str | None = Field(
        None, description="Expected 'aud' claim for OIDC tokens. If provided, must not be empty."
    )
    auto_create_projects: bool | None = Field(None, description="Automatically create projects from OIDC tokens")
    sync_teams: bool | None = Field(None, description="Sync GitHub team members to local teams")
    access_token: str | None = Field(None, description="Personal Access Token for GitHub API operations")

    _audience_not_blank = field_validator("oidc_audience")(validate_optional_audience_not_blank)


class GitHubInstanceResponse(GitHubInstanceBase):
    """Schema for GitHub instance response."""

    # No blank-check here: the response reflects stored state verbatim so
    # admins can see and fix instances whose audience is null.
    oidc_audience: str | None = Field(
        None, description="Expected 'aud' claim for OIDC tokens. Null means not yet configured (will 403 on ingest)."
    )

    id: str = Field(..., description="Unique identifier")
    has_access_token: bool = Field(False, description="Whether an API access token is configured")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="User ID who created this instance")
    last_modified_at: datetime | None = Field(None, description="Last modification timestamp")

    model_config = ConfigDict(from_attributes=True)


class GitHubInstanceList(BaseModel):
    """Paginated list of GitHub instances."""

    items: list[GitHubInstanceResponse]
    total: int
    page: int
    size: int
    pages: int


class GitHubOrgTeam(BaseModel):
    """One team of an organisation, as offered for binding."""

    id: int = Field(..., description="Numeric team id; the binding is stored on this, not on the slug")
    slug: str = Field(..., description="URL slug the team API is addressed by")
    name: str = Field(..., description="Display name")
    parent_slug: str | None = Field(None, description="Slug of the parent team, null for a top-level team")
    parent_name: str | None = Field(None, description="Display name of the parent team")


class GitHubInstanceTestConnectionResponse(BaseModel):
    """Response for OIDC endpoint connectivity test."""

    success: bool = Field(..., description="Whether the connectivity test succeeded")
    message: str = Field(..., description="Status message")
    instance_name: str = Field(..., description="Name of the tested instance")
    url: str = Field(..., description="URL of the tested instance")
