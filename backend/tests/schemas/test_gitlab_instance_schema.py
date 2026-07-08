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
