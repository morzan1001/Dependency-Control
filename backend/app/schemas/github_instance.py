import re
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.github_instance import is_shared_github_issuer
from app.schemas._vcs_instance import VcsInstanceBase, VcsInstanceCreate, VcsInstanceResponse, VcsInstanceUpdate

AUTO_CREATE_NEEDS_OWNERS = (
    "Auto-creating projects on the shared github.com issuer needs at least one allowed owner id, "
    "since every github.com repository can mint tokens for it"
)

_OWNER_ID = re.compile(r"[0-9]+")


def lacks_required_owners(url: str, auto_create_projects: bool, allowed_owner_ids: list[str]) -> bool:
    return auto_create_projects and is_shared_github_issuer(url) and not allowed_owner_ids


def _validate_owner_ids(value: list[str] | None) -> list[str]:
    if value is None:
        raise ValueError("allowed_owner_ids must be a list; send [] to clear it")
    for owner_id in value:
        if not _OWNER_ID.fullmatch(owner_id):
            raise ValueError(f"allowed_owner_ids holds numeric repository_owner_id values, not logins: {owner_id!r}")
    return value


class GitHubInstanceBase(VcsInstanceBase):
    github_url: str | None = Field(None, description="GitHub web URL (e.g. 'https://github.com')")
    allowed_owner_ids: list[str] = Field(
        default_factory=list,
        description="Numeric repository_owner_id claims whose tokens are accepted; empty accepts every owner",
    )


class GitHubInstanceCreate(GitHubInstanceBase, VcsInstanceCreate):
    """Schema for creating a new GitHub instance."""

    _owner_ids_numeric = field_validator("allowed_owner_ids")(_validate_owner_ids)

    @model_validator(mode="after")
    def validate_owner_scope(self) -> Self:
        if lacks_required_owners(self.url, self.auto_create_projects, self.allowed_owner_ids):
            raise ValueError(AUTO_CREATE_NEEDS_OWNERS)
        return self


class GitHubInstanceUpdate(VcsInstanceUpdate):
    """Schema for updating a GitHub instance. All fields optional."""

    github_url: str | None = Field(None, description="GitHub web URL")
    allowed_owner_ids: list[str] | None = Field(
        None, description="Numeric repository_owner_id claims whose tokens are accepted; [] accepts every owner"
    )

    _owner_ids_numeric = field_validator("allowed_owner_ids")(_validate_owner_ids)


class GitHubInstanceResponse(GitHubInstanceBase, VcsInstanceResponse):
    """Schema for GitHub instance response."""


class GitHubOrgTeam(BaseModel):
    """One team of an organisation, as offered for binding."""

    id: int = Field(..., description="Numeric team id; the binding is stored on this, not on the slug")
    slug: str = Field(..., description="URL slug the team API is addressed by")
    name: str = Field(..., description="Display name")
    parent_name: str | None = Field(None, description="Display name of the parent team")


class GitHubInstanceTestConnectionResponse(BaseModel):
    """Response for OIDC endpoint connectivity test."""

    success: bool = Field(..., description="Whether the connectivity test succeeded")
    message: str = Field(..., description="Status message")
    instance_name: str = Field(..., description="Name of the tested instance")
    url: str = Field(..., description="URL of the tested instance")
