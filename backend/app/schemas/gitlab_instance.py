from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class GitLabInstanceBase(BaseModel):
    """Base schema for GitLab instance."""

    name: str = Field(..., description="Human-readable name (e.g. 'GitLab.com', 'Internal GitLab')")
    url: str = Field(..., description="Base URL of the GitLab instance (e.g. 'https://gitlab.com')")
    description: Optional[str] = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")
    is_default: bool = Field(False, description="Whether this is the default instance")
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens from this instance")
    auto_create_projects: bool = Field(False, description="Automatically create projects from OIDC tokens")
    sync_teams: bool = Field(False, description="Sync GitLab group members to local teams")


class GitLabInstanceCreate(GitLabInstanceBase):
    """Schema for creating a new GitLab instance."""

    access_token: str = Field(..., description="Personal or Group Access Token with 'api' scope")


class GitLabInstanceUpdate(BaseModel):
    """Schema for updating a GitLab instance. All fields optional."""

    name: Optional[str] = Field(None, description="Human-readable name")
    url: Optional[str] = Field(None, description="Base URL of the GitLab instance")
    description: Optional[str] = Field(None, description="Optional description")
    is_active: Optional[bool] = Field(None, description="Whether this instance is active")
    is_default: Optional[bool] = Field(None, description="Whether this is the default instance")
    access_token: Optional[str] = Field(None, description="Personal or Group Access Token with 'api' scope")
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens")
    auto_create_projects: Optional[bool] = Field(None, description="Automatically create projects from OIDC tokens")
    sync_teams: Optional[bool] = Field(None, description="Sync GitLab group members to local teams")


class GitLabInstanceResponse(GitLabInstanceBase):
    """Schema for GitLab instance response (without access_token)."""

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
