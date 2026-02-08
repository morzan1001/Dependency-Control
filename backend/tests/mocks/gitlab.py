"""Reusable GitLab mock objects and factory functions."""

from app.models.gitlab_api import (
    GitLabMember,
    GitLabMergeRequest,
    GitLabNamespace,
    GitLabNote,
    GitLabProjectDetails,
    OIDCPayload,
)
from app.models.gitlab_instance import GitLabInstance


def make_gitlab_instance(
    id="test-instance-id",
    name="Test GitLab",
    url="https://gitlab.test.com",
    access_token="glpat-test-token",
    oidc_audience="https://app.example.com",
    is_active=True,
    is_default=False,
    auto_create_projects=True,
    sync_teams=True,
    created_by="admin",
    **kwargs,
):
    """Create a GitLabInstance with sensible defaults for testing."""
    return GitLabInstance(
        id=id,
        name=name,
        url=url,
        access_token=access_token,
        oidc_audience=oidc_audience,
        is_active=is_active,
        is_default=is_default,
        auto_create_projects=auto_create_projects,
        sync_teams=sync_teams,
        created_by=created_by,
        **kwargs,
    )


def instance_a():
    """Create standard test instance A (fresh copy each call)."""
    return make_gitlab_instance(
        id="instance-a-id",
        name="GitLab A",
        url="https://gitlab-a.com",
        access_token="glpat-token-a",
    )


def instance_b():
    """Create standard test instance B (fresh copy each call)."""
    return make_gitlab_instance(
        id="instance-b-id",
        name="GitLab B",
        url="https://gitlab-b.com",
        access_token="glpat-token-b",
        auto_create_projects=False,
        sync_teams=False,
    )


def make_oidc_payload(**kwargs):
    """Create an OIDCPayload with sensible defaults."""
    defaults = {"project_id": "42", "project_path": "group/project"}
    defaults.update(kwargs)
    return OIDCPayload(**defaults)


def make_merge_request(**kwargs):
    """Create a GitLabMergeRequest with sensible defaults."""
    defaults = {"iid": 1, "state": "opened", "draft": False, "work_in_progress": False}
    defaults.update(kwargs)
    return GitLabMergeRequest(**defaults)


def make_note(**kwargs):
    """Create a GitLabNote with sensible defaults."""
    defaults = {"id": 1, "body": ""}
    defaults.update(kwargs)
    return GitLabNote(**defaults)


def make_member(**kwargs):
    """Create a GitLabMember with sensible defaults."""
    defaults = {"username": "user", "email": "user@test.com", "access_level": 30}
    defaults.update(kwargs)
    return GitLabMember(**defaults)


def make_project_details(namespace_kind="group", namespace_id=42, namespace_path="group"):
    """Create a GitLabProjectDetails with a namespace."""
    return GitLabProjectDetails(
        namespace=GitLabNamespace(kind=namespace_kind, id=namespace_id, full_path=namespace_path)
    )
