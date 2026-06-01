from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas._oidc_audience import (
    validate_audience_not_blank,
    validate_optional_audience_not_blank,
)


class GitHubInstanceBase(BaseModel):
    """Base schema for GitHub instance.

    SECURITY (Finding 7 / W1.1): ``oidc_audience`` is hard-required on
    create/update. OIDC tokens are verified with mandatory, fail-closed
    audience checking, so an instance without an audience could never
    authenticate a token anyway. Creating/updating an instance with an
    empty/missing audience is rejected with HTTP 422. The configured audience
    must match the GitHub Actions OIDC token request ``audience``.

    Note: the audience field and its blank-check live on the Create/Update
    schemas, NOT here — the Response schema must still serialize legacy
    instances whose audience is null (see ``GitHubInstanceResponse``).
    """

    name: str = Field(..., description="Human-readable name (e.g. 'GitHub.com', 'GitHub Enterprise')")
    url: str = Field(..., description="OIDC issuer URL (e.g. 'https://token.actions.githubusercontent.com')")
    github_url: Optional[str] = Field(None, description="GitHub web URL (e.g. 'https://github.com')")
    description: Optional[str] = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")
    auto_create_projects: bool = Field(False, description="Automatically create projects from OIDC tokens")


class GitHubInstanceCreate(GitHubInstanceBase):
    """Schema for creating a new GitHub instance."""

    oidc_audience: str = Field(
        ...,
        min_length=1,
        description="REQUIRED expected 'aud' claim for OIDC tokens. "
        "Must match the GitHub Actions token request 'audience'.",
    )
    access_token: Optional[str] = Field(None, description="Personal Access Token for GitHub API operations")

    _audience_not_blank = field_validator("oidc_audience")(validate_audience_not_blank)


class GitHubInstanceUpdate(BaseModel):
    """Schema for updating a GitHub instance. All fields optional."""

    name: Optional[str] = Field(None, description="Human-readable name")
    url: Optional[str] = Field(None, description="OIDC issuer URL")
    github_url: Optional[str] = Field(None, description="GitHub web URL")
    description: Optional[str] = Field(None, description="Optional description")
    is_active: Optional[bool] = Field(None, description="Whether this instance is active")
    oidc_audience: Optional[str] = Field(
        None, description="Expected 'aud' claim for OIDC tokens. If provided, must not be empty."
    )
    auto_create_projects: Optional[bool] = Field(None, description="Automatically create projects from OIDC tokens")
    access_token: Optional[str] = Field(None, description="Personal Access Token for GitHub API operations")

    _audience_not_blank = field_validator("oidc_audience")(validate_optional_audience_not_blank)


class GitHubInstanceResponse(GitHubInstanceBase):
    """Schema for GitHub instance response."""

    # Responses must be able to represent legacy instances created before
    # oidc_audience became required, so admins can see (and fix) them. There is
    # deliberately NO blank-check validator here — the create/update validation
    # enforces the requirement; the response reflects stored state verbatim.
    oidc_audience: Optional[str] = Field(
        None, description="Expected 'aud' claim for OIDC tokens. Null means not yet configured (will 403 on ingest)."
    )

    id: str = Field(..., description="Unique identifier")
    has_access_token: bool = Field(False, description="Whether an API access token is configured")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="User ID who created this instance")
    last_modified_at: Optional[datetime] = Field(None, description="Last modification timestamp")

    model_config = ConfigDict(from_attributes=True)


class GitHubInstanceList(BaseModel):
    """Paginated list of GitHub instances."""

    items: List[GitHubInstanceResponse]
    total: int
    page: int
    size: int
    pages: int


class GitHubInstanceTestConnectionResponse(BaseModel):
    """Response for OIDC endpoint connectivity test."""

    success: bool = Field(..., description="Whether the connectivity test succeeded")
    message: str = Field(..., description="Status message")
    instance_name: str = Field(..., description="Name of the tested instance")
    url: str = Field(..., description="URL of the tested instance")
