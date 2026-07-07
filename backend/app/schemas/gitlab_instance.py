from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas._oidc_audience import (
    validate_audience_not_blank,
    validate_optional_audience_not_blank,
)


class GitLabInstanceBase(BaseModel):
    """Base schema for GitLab instance.

    SECURITY (Finding 7 / W1.1): ``oidc_audience`` is hard-required on
    create/update. OIDC tokens are verified with mandatory, fail-closed
    audience checking, so an instance without an audience could never
    authenticate a token anyway. Creating/updating an instance with an
    empty/missing audience is rejected with HTTP 422. The configured audience
    must match the CI pipeline's requested ``aud`` (GitLab ``id_tokens[].aud``).

    Note: the audience field and its blank-check live on the Create/Update
    schemas, NOT here — the Response schema must still serialize legacy
    instances whose audience is null (see ``GitLabInstanceResponse``).
    """

    name: str = Field(..., description="Human-readable name (e.g. 'GitLab.com', 'Internal GitLab')")
    url: str = Field(..., description="Base URL of the GitLab instance (e.g. 'https://gitlab.com')")
    description: Optional[str] = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")
    is_default: bool = Field(False, description="Whether this is the default instance")
    auto_create_projects: bool = Field(False, description="Automatically create projects from OIDC tokens")
    sync_teams: bool = Field(False, description="Sync GitLab group members to local teams")
    team_sync_depth: int = Field(
        1,
        ge=0,
        description="GitLab group path depth for team creation. "
        "1 = top-level group only (e.g. 'mo'), 2 = two levels (e.g. 'mo/edge'), "
        "0 = full path.",
    )


class GitLabInstanceCreate(GitLabInstanceBase):
    """Schema for creating a new GitLab instance."""

    oidc_audience: str = Field(
        ...,
        min_length=1,
        description="REQUIRED expected 'aud' claim for OIDC tokens from this instance. "
        "Must match the CI pipeline's requested audience (GitLab id_tokens[].aud).",
    )
    access_token: Optional[str] = Field(None, description="Personal or Group Access Token with 'api' scope")

    _audience_not_blank = field_validator("oidc_audience")(validate_audience_not_blank)

    @model_validator(mode="after")
    def validate_token_dependent_features(self) -> "GitLabInstanceCreate":
        if self.sync_teams and not self.access_token:
            raise ValueError("An access token is required to enable team syncing")
        return self


class GitLabInstanceUpdate(BaseModel):
    """Schema for updating a GitLab instance. All fields optional."""

    name: Optional[str] = Field(None, description="Human-readable name")
    url: Optional[str] = Field(None, description="Base URL of the GitLab instance")
    description: Optional[str] = Field(None, description="Optional description")
    is_active: Optional[bool] = Field(None, description="Whether this instance is active")
    is_default: Optional[bool] = Field(None, description="Whether this is the default instance")
    access_token: Optional[str] = Field(None, description="Personal or Group Access Token with 'api' scope")
    oidc_audience: Optional[str] = Field(
        None, description="Expected 'aud' claim for OIDC tokens. If provided, must not be empty."
    )
    auto_create_projects: Optional[bool] = Field(None, description="Automatically create projects from OIDC tokens")
    sync_teams: Optional[bool] = Field(None, description="Sync GitLab group members to local teams")
    team_sync_depth: Optional[int] = Field(
        None, ge=0, description="GitLab group path depth for team creation (0 = full path)."
    )

    _audience_not_blank = field_validator("oidc_audience")(validate_optional_audience_not_blank)


class GitLabInstanceResponse(GitLabInstanceBase):
    """Schema for GitLab instance response (without access_token)."""

    # Responses must be able to represent legacy instances created before
    # oidc_audience became required, so admins can see (and fix) them. There is
    # deliberately NO blank-check validator here — the create/update validation
    # enforces the requirement; the response reflects stored state verbatim.
    oidc_audience: Optional[str] = Field(
        None, description="Expected 'aud' claim for OIDC tokens. Null means not yet configured (will 403 on ingest)."
    )

    id: str = Field(..., description="Unique identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="User ID who created this instance")
    last_modified_at: Optional[datetime] = Field(None, description="Last modification timestamp")

    # Additional info (not in base)
    token_configured: bool = Field(
        False, description="Whether an access token is configured (without exposing the token)"
    )

    model_config = ConfigDict(from_attributes=True)


class GitLabInstanceList(BaseModel):
    """Paginated list of GitLab instances."""

    items: List[GitLabInstanceResponse]
    total: int
    page: int
    size: int
    pages: int


class GitLabInstanceTestConnectionResponse(BaseModel):
    """Response for connection test."""

    success: bool = Field(..., description="Whether the connection test succeeded")
    message: str = Field(..., description="Status message")
    gitlab_version: Optional[str] = Field(None, description="GitLab version if successful")
    instance_name: str = Field(..., description="Name of the tested instance")
    url: str = Field(..., description="URL of the tested instance")


class GitLabInstanceStats(BaseModel):
    """Statistics for a GitLab instance."""

    instance_id: str
    instance_name: str
    project_count: int = Field(..., description="Number of projects linked to this instance")
    active_project_count: int = Field(..., description="Number of active projects")
    last_scan_at: Optional[datetime] = Field(None, description="Timestamp of most recent scan")
