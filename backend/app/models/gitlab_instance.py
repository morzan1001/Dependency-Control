import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId


class GitLabInstance(BaseModel):
    """
    Represents a configured GitLab instance.

    Each instance has its own:
    - URL and OIDC issuer
    - Access token for API operations
    - Configuration flags (auto-create, team sync)
    - Unique identifier for project references
    """

    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )

    # Identity
    name: str = Field(..., description="Human-readable name (e.g. 'GitLab.com', 'Internal GitLab')")
    url: str = Field(..., description="Base URL of the GitLab instance (e.g. 'https://gitlab.com')")
    description: Optional[str] = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")
    is_default: bool = Field(False, description="Whether this is the default instance for new projects")

    # Authentication
    access_token: Optional[str] = Field(
        None,
        exclude=True,  # Never expose in API responses
        description="Personal or Group Access Token with 'api' scope for GitLab API operations",
    )
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens from this instance")

    # Features
    auto_create_projects: bool = Field(
        False, description="Automatically create projects from OIDC tokens if they don't exist"
    )
    sync_teams: bool = Field(False, description="Sync GitLab group members to local teams")

    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = Field(..., description="User ID of the admin who created this instance")
    last_modified_at: Optional[datetime] = None

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
