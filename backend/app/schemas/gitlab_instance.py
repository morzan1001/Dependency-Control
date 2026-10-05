import re
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.gitlab_instance import is_shared_gitlab_issuer
from app.schemas._not_null import reject_null
from app.schemas._vcs_instance import VcsInstanceBase, VcsInstanceCreate, VcsInstanceResponse, VcsInstanceUpdate

AUTO_CREATE_NEEDS_NAMESPACES = (
    "Auto-creating projects on gitlab.com needs at least one allowed namespace, "
    "since every gitlab.com project can mint tokens for it"
)

_TOP_LEVEL_GROUP = re.compile(r"[A-Za-z0-9_.-]+")


def lacks_required_namespaces(url: str, auto_create_projects: bool, allowed_namespaces: list[str]) -> bool:
    return auto_create_projects and is_shared_gitlab_issuer(url) and not allowed_namespaces


def _validate_namespaces(value: list[str] | None) -> list[str]:
    if value is None:
        raise ValueError("allowed_namespaces must be a list; send [] to clear it")
    for namespace in value:
        if not _TOP_LEVEL_GROUP.fullmatch(namespace):
            raise ValueError(
                f"allowed_namespaces holds top-level group paths such as 'acme', without '/': {namespace!r}"
            )
    return value


class GitLabInstanceBase(VcsInstanceBase):
    team_sync_depth: int = Field(
        1,
        ge=0,
        description="GitLab group path depth for team creation. "
        "1 = top-level group only (e.g. 'mo'), 2 = two levels (e.g. 'mo/edge'), "
        "0 = full path.",
    )
    allowed_namespaces: list[str] = Field(
        default_factory=list,
        description="Top-level groups whose projects' tokens are accepted (case-insensitive); empty accepts every "
        "project",
    )


class GitLabInstanceCreate(GitLabInstanceBase, VcsInstanceCreate):
    """Schema for creating a new GitLab instance."""

    _namespaces_top_level = field_validator("allowed_namespaces")(_validate_namespaces)

    @model_validator(mode="after")
    def validate_namespace_scope(self) -> Self:
        if lacks_required_namespaces(self.url, self.auto_create_projects, self.allowed_namespaces):
            raise ValueError(AUTO_CREATE_NEEDS_NAMESPACES)
        return self


class GitLabInstanceUpdate(VcsInstanceUpdate):
    """Schema for updating a GitLab instance. All fields optional."""

    team_sync_depth: int | None = Field(
        None, ge=0, description="GitLab group path depth for team creation (0 = full path)."
    )
    allowed_namespaces: list[str] | None = Field(
        None, description="Top-level groups whose projects' tokens are accepted; [] accepts every project"
    )

    _depth_not_null = field_validator("team_sync_depth")(reject_null)
    _namespaces_top_level = field_validator("allowed_namespaces")(_validate_namespaces)


class GitLabInstanceResponse(GitLabInstanceBase, VcsInstanceResponse):
    """Schema for GitLab instance response (without access_token)."""


class GitLabGroupOption(BaseModel):
    """One group of an instance, as offered for binding."""

    id: int = Field(..., description="Numeric group id; the binding is stored on this, not on the path")
    full_path: str = Field(..., description="Full path, which tells two same-named subgroups apart")
    name: str = Field(..., description="Display name")


class GitLabInstanceTestConnectionResponse(BaseModel):
    """Response for connection test."""

    success: bool = Field(..., description="Whether the connection test succeeded")
    message: str = Field(..., description="Status message")
    gitlab_version: str | None = Field(None, description="GitLab version if successful")
    instance_name: str = Field(..., description="Name of the tested instance")
    url: str = Field(..., description="URL of the tested instance")
