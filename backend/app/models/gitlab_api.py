"""
Pydantic models for GitLab API responses and OIDC token payloads.

These models represent data returned by the GitLab REST API and OIDC tokens.
All use extra="ignore" to silently discard fields we don't use.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict


class OIDCPayload(BaseModel):
    """Validated OIDC JWT token payload from GitLab CI/CD."""

    model_config = ConfigDict(extra="ignore")

    project_id: str
    project_path: str
    user_email: Optional[str] = None


class GitLabNamespace(BaseModel):
    """Namespace sub-object within a GitLab project response."""

    model_config = ConfigDict(extra="ignore")

    kind: str
    id: int
    full_path: str


class GitLabProjectDetails(BaseModel):
    """GitLab project details from GET /projects/:id."""

    model_config = ConfigDict(extra="ignore")

    namespace: Optional[GitLabNamespace] = None


class GitLabMergeRequest(BaseModel):
    """Merge request from GET /projects/:id/repository/commits/:sha/merge_requests."""

    model_config = ConfigDict(extra="ignore")

    iid: int
    state: str
    draft: bool = False
    work_in_progress: bool = False


class GitLabNote(BaseModel):
    """Note (comment) from GET /projects/:id/merge_requests/:iid/notes."""

    model_config = ConfigDict(extra="ignore")

    id: int
    body: str = ""


class GitLabMember(BaseModel):
    """Member from GET /groups/:id/members/all or /projects/:id/members/all."""

    model_config = ConfigDict(extra="ignore")

    username: Optional[str] = None
    email: Optional[str] = None
    access_level: int = 0
