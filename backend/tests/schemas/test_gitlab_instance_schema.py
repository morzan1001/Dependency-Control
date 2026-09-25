"""GitLab instance Create/Update/Response schemas carry team_sync_depth."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.gitlab_instance import (
    GitLabInstanceCreate,
    GitLabInstanceResponse,
    GitLabInstanceUpdate,
)


def test_create_accepts_and_retains_team_sync_depth():
    schema = GitLabInstanceCreate(
        name="Internal GitLab",
        url="https://gitlab.example.com",
        oidc_audience="my-aud",
        team_sync_depth=2,
    )
    assert schema.team_sync_depth == 2
    assert schema.model_dump()["team_sync_depth"] == 2


def test_create_team_sync_depth_defaults_to_one():
    schema = GitLabInstanceCreate(
        name="Internal GitLab",
        url="https://gitlab.example.com",
        oidc_audience="my-aud",
    )
    assert schema.team_sync_depth == 1


def test_create_team_sync_depth_zero_means_full_path():
    schema = GitLabInstanceCreate(
        name="Internal GitLab",
        url="https://gitlab.example.com",
        oidc_audience="my-aud",
        team_sync_depth=0,
    )
    assert schema.team_sync_depth == 0


def test_create_rejects_negative_team_sync_depth():
    with pytest.raises(ValidationError):
        GitLabInstanceCreate(
            name="Internal GitLab",
            url="https://gitlab.example.com",
            oidc_audience="my-aud",
            team_sync_depth=-1,
        )


def test_update_includes_team_sync_depth_when_set():
    update = GitLabInstanceUpdate(team_sync_depth=2)
    dumped = update.model_dump(exclude_unset=True)
    assert dumped == {"team_sync_depth": 2}


def test_update_omits_team_sync_depth_when_unset():
    update = GitLabInstanceUpdate(name="renamed")
    dumped = update.model_dump(exclude_unset=True)
    assert "team_sync_depth" not in dumped


def test_response_serializes_team_sync_depth():
    resp = GitLabInstanceResponse(
        id="abc123",
        name="Internal GitLab",
        url="https://gitlab.example.com",
        oidc_audience="my-aud",
        team_sync_depth=2,
        created_at=datetime.now(timezone.utc),
        created_by="user-1",
    )
    assert resp.model_dump()["team_sync_depth"] == 2


_GITLAB_COM = "https://gitlab.com"


def _create(**overrides):
    fields = {"name": "GitLab.com", "url": _GITLAB_COM, "oidc_audience": "my-aud", **overrides}
    return GitLabInstanceCreate(**fields)


@pytest.mark.parametrize("url", [_GITLAB_COM, f"{_GITLAB_COM}/"])
def test_create_refuses_auto_create_on_gitlab_com_without_a_namespace_list(url):
    with pytest.raises(ValidationError, match="allowed namespace"):
        _create(url=url, auto_create_projects=True)


def test_create_allows_auto_create_on_gitlab_com_with_a_namespace_list():
    assert _create(auto_create_projects=True, allowed_namespaces=["acme"]).allowed_namespaces == ["acme"]


def test_create_allows_gitlab_com_without_a_list_when_auto_create_is_off():
    assert _create().allowed_namespaces == []


def test_create_leaves_the_list_optional_for_a_self_managed_instance():
    schema = _create(url="https://gitlab.example.com", auto_create_projects=True)
    assert schema.auto_create_projects is True


@pytest.mark.parametrize("namespace", ["acme/platform", "", " acme", "/acme"])
def test_create_refuses_anything_but_a_top_level_group_path(namespace):
    """Only the top-level group of project_path is compared, so a subgroup entry would admit nobody."""
    with pytest.raises(ValidationError, match="top-level"):
        _create(allowed_namespaces=[namespace])


def test_update_omits_the_namespace_list_when_unset():
    assert "allowed_namespaces" not in GitLabInstanceUpdate(name="renamed").model_dump(exclude_unset=True)


def test_update_refuses_a_null_namespace_list():
    with pytest.raises(ValidationError):
        GitLabInstanceUpdate(allowed_namespaces=None)


def test_update_refuses_a_subgroup_path():
    with pytest.raises(ValidationError, match="top-level"):
        GitLabInstanceUpdate(allowed_namespaces=["acme/platform"])


def test_response_serializes_the_namespace_list():
    resp = GitLabInstanceResponse(
        id="abc123",
        name="GitLab.com",
        url=_GITLAB_COM,
        allowed_namespaces=["acme"],
        created_at=datetime.now(timezone.utc),
        created_by="user-1",
    )
    assert resp.model_dump()["allowed_namespaces"] == ["acme"]
