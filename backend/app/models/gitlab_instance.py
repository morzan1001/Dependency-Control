from datetime import datetime
from typing import Optional

from pydantic import ConfigDict, Field

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class GitLabInstance(MongoDocument, CreatedAtModel):
    """
    Represents a configured GitLab instance.

    Each instance has its own:
    - URL and OIDC issuer
    - Access token for API operations
    - Configuration flags (auto-create, team sync)
    - Unique identifier for project references
    """

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
    # SECURITY (Finding 7 / W1.1): oidc_audience is effectively REQUIRED. The
    # create/update API schemas reject empty/missing values (422), and OIDC
    # token validation fails closed when it is unset (403 on ingest). The stored
    # field stays Optional ONLY so legacy DB documents written before this change
    # still hydrate (and remain visible/fixable) rather than crashing on read.
    oidc_audience: Optional[str] = Field(None, description="Expected 'aud' claim for OIDC tokens from this instance")

    # Features
    auto_create_projects: bool = Field(
        False, description="Automatically create projects from OIDC tokens if they don't exist"
    )
    sync_teams: bool = Field(False, description="Sync GitLab group members to local teams")
    team_sync_depth: int = Field(
        1,
        description="GitLab group path depth for team creation. "
        "1 = top-level group only (e.g. 'mo'), "
        "2 = two levels (e.g. 'mo/edge'), "
        "0 = full path (current behavior)",
    )

    # Metadata
    created_by: str = Field(..., description="User ID of the admin who created this instance")
    last_modified_at: Optional[datetime] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)
