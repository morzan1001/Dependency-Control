"""Fields and validators the GitHub and GitLab instance schemas share."""

from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas._not_null import reject_null

_URL_DESCRIPTION = "OIDC issuer URL"
_SYNC_TEAMS_DESCRIPTION = "Sync team or group members to local teams"
_ACCESS_TOKEN_DESCRIPTION = "Access token for the provider's API"


def _strip_trailing_slash(value: str) -> str:
    """The OIDC issuer lookup matches the URL without a trailing slash."""
    return value.rstrip("/")


def _validate_audience_not_blank(value: str | None) -> str:
    """Reject a null or blank audience (fail-closed) and store it trimmed; the token check matches it exactly."""
    stripped = (value or "").strip()
    if not stripped:
        raise ValueError("oidc_audience must not be empty")
    return stripped


class VcsInstanceBase(BaseModel):
    """oidc_audience is declared per schema so the Response can serialize an instance whose audience is null."""

    name: str = Field(..., description="Human-readable name")
    url: str = Field(..., description=_URL_DESCRIPTION)
    description: str | None = Field(None, description="Optional description of this instance")
    is_active: bool = Field(True, description="Whether this instance is currently active")
    auto_create_projects: bool = Field(False, description="Automatically create projects from OIDC tokens")
    sync_teams: bool = Field(False, description=_SYNC_TEAMS_DESCRIPTION)


class VcsInstanceCreate(VcsInstanceBase):
    oidc_audience: str = Field(
        ...,
        min_length=1,
        description="REQUIRED expected 'aud' claim for OIDC tokens. Must match the audience the CI job requests.",
    )
    access_token: str | None = Field(None, description=_ACCESS_TOKEN_DESCRIPTION)

    _audience_not_blank = field_validator("oidc_audience")(_validate_audience_not_blank)
    _url_normalised = field_validator("url")(_strip_trailing_slash)

    @model_validator(mode="after")
    def validate_team_sync_token(self) -> Self:
        if self.sync_teams and not self.access_token:
            raise ValueError("An access token is required to enable team syncing")
        return self


class VcsInstanceUpdate(BaseModel):
    name: str | None = Field(None, description="Human-readable name")
    url: str | None = Field(None, description=_URL_DESCRIPTION)
    description: str | None = Field(None, description="Optional description")
    is_active: bool | None = Field(None, description="Whether this instance is active")
    oidc_audience: str | None = Field(
        None, description="Expected 'aud' claim for OIDC tokens. If provided, must not be empty."
    )
    auto_create_projects: bool | None = Field(None, description="Automatically create projects from OIDC tokens")
    sync_teams: bool | None = Field(None, description=_SYNC_TEAMS_DESCRIPTION)
    access_token: str | None = Field(None, description=_ACCESS_TOKEN_DESCRIPTION)

    _not_null = field_validator("name", "url", "is_active", "auto_create_projects", "sync_teams")(reject_null)
    _audience_not_blank = field_validator("oidc_audience")(_validate_audience_not_blank)
    _url_normalised = field_validator("url")(_strip_trailing_slash)


class VcsInstanceResponse(VcsInstanceBase):
    oidc_audience: str | None = Field(
        None, description="Expected 'aud' claim for OIDC tokens. Null means not yet configured (will 403 on ingest)."
    )

    id: str = Field(..., description="Unique identifier")
    token_configured: bool = Field(
        False, description="Whether an access token is configured (without exposing the token)"
    )
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="User ID who created this instance")
    last_modified_at: datetime | None = Field(None, description="Last modification timestamp")

    model_config = ConfigDict(from_attributes=True)
