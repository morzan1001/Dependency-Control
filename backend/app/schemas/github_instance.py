from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class GitHubInstanceBase(BaseModel):
    """Base schema for GitHub instance."""

    name: str = Field(..., description="Human-readable name (e.g. 'GitHub.com', 'GitHub Enterprise')")
    url: str = Field(..., description="OIDC issuer URL (e.g. 'https://token.actions.githubusercontent.com')")
    github_url: Optional[str] = Field(None, description="GitHub web URL (e.g. 'https://github.com')")
    description: Optional[str] = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens")
    auto_create_projects: bool = Field(False, description="Automatically create projects from OIDC tokens")


class GitHubInstanceCreate(GitHubInstanceBase):
    """Schema for creating a new GitHub instance."""

    access_token: Optional[str] = Field(None, description="Personal Access Token for GitHub API operations")


class GitHubInstanceUpdate(BaseModel):
    """Schema for updating a GitHub instance. All fields optional."""

    name: Optional[str] = Field(None, description="Human-readable name")
    url: Optional[str] = Field(None, description="OIDC issuer URL")
    github_url: Optional[str] = Field(None, description="GitHub web URL")
    description: Optional[str] = Field(None, description="Optional description")
    is_active: Optional[bool] = Field(None, description="Whether this instance is active")
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens")
    auto_create_projects: Optional[bool] = Field(None, description="Automatically create projects from OIDC tokens")
    access_token: Optional[str] = Field(None, description="Personal Access Token for GitHub API operations")


class GitHubInstanceResponse(GitHubInstanceBase):
    """Schema for GitHub instance response."""

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
