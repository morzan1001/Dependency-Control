"""Reusable GitLab mock objects and factory functions."""

from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

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


# The user GET /user resolves the instance token to.
BOT_USER_ID = 4242


def make_merge_request(**kwargs):
    """A GitLabMergeRequest parsed from a GET /projects/:id/repository/commits/:sha/merge_requests item."""
    defaults = {"iid": 1, "state": "opened", "draft": False, "work_in_progress": False, "sha": "abc"}
    defaults.update(kwargs)
    return GitLabMergeRequest.model_validate(defaults)


def make_note(author_id=BOT_USER_ID, **kwargs):
    """A GitLabNote parsed from a GET /projects/:id/merge_requests/:iid/notes item."""
    defaults = {"id": 1, "body": "", "system": False, "author": {"id": author_id, "username": f"user{author_id}"}}
    defaults.update(kwargs)
    return GitLabNote.model_validate(defaults)


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


async def sync_team(service, project_details, **kwargs):
    """A sync against a GitLab whose project read answers ``project_details``."""
    with patch.object(service, "get_project_details", new=AsyncMock(return_value=project_details)):
        return await service.sync_team_from_gitlab(**kwargs)


@contextmanager
def make_repositories(existing_team=None, user_doc=None) -> Iterator[tuple[MagicMock, MagicMock]]:
    """The two repositories a GitLab sync works through, recording what it hands them.

    ``user_doc`` answers the verified-email lookup every member is resolved through.

    ``add_binding_if_absent`` is left recording rather than working: it is the one door an existing
    team can be bound through, and a sync must never reach it.
    """
    team_repo = MagicMock()
    team_repo.get_raw_by_binding = AsyncMock(return_value=existing_team)
    team_repo.update_with_binding = AsyncMock()
    team_repo.create_bound = AsyncMock(side_effect=lambda team: team.model_dump(by_alias=True))
    team_repo.add_binding_if_absent = AsyncMock()

    user_repo = MagicMock()
    user_repo.verified_users_by_email = AsyncMock(
        side_effect=lambda emails: {email.lower(): {**user_doc, "email": email} for email in emails} if user_doc else {}
    )

    with (
        patch("app.services.gitlab.TeamRepository", return_value=team_repo),
        patch("app.services.gitlab.UserRepository", return_value=user_repo),
    ):
        yield team_repo, user_repo
