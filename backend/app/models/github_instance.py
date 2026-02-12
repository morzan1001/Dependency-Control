import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId


class GitHubInstance(BaseModel):
    """
    Represents a configured GitHub instance (github.com or GitHub Enterprise Server).

    Each instance has its own:
    - OIDC issuer URL for token validation
    - Configuration flags (auto-create)
    - Unique identifier for project references
    """

    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )

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
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens from this instance")

    # Features
    auto_create_projects: bool = Field(
        False, description="Automatically create projects from OIDC tokens if they don't exist"
    )

    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = Field(..., description="User ID of the admin who created this instance")
    last_modified_at: Optional[datetime] = None

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
