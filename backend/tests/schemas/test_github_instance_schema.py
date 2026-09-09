"""GitHub instance Create/Update/Response schemas carry sync_teams."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.github_instance import (
    GitHubInstanceCreate,
    GitHubInstanceResponse,
    GitHubInstanceUpdate,
)

_URL = "https://token.actions.githubusercontent.com"


def test_create_defaults_sync_teams_to_off():
    schema = GitHubInstanceCreate(name="GitHub.com", url=_URL, oidc_audience="dependency-control")
    assert schema.sync_teams is False


def test_create_retains_sync_teams():
    schema = GitHubInstanceCreate(
        name="GitHub.com",
        url=_URL,
        oidc_audience="dependency-control",
        access_token="ghp-secret",
        sync_teams=True,
    )
    assert schema.model_dump()["sync_teams"] is True


def test_create_rejects_sync_teams_without_an_access_token():
    """Team sync reads the API with the instance token; without one it silently syncs nothing."""
    with pytest.raises(ValidationError):
        GitHubInstanceCreate(name="GitHub.com", url=_URL, oidc_audience="dependency-control", sync_teams=True)


def test_update_omits_sync_teams_when_unset():
    """Tri-state: an unset field must not carry a default that silently turns the feature off."""
    update = GitHubInstanceUpdate(name="renamed")
    assert update.sync_teams is None
    assert "sync_teams" not in update.model_dump(exclude_unset=True)


def test_update_includes_sync_teams_when_set():
    assert GitHubInstanceUpdate(sync_teams=True).model_dump(exclude_unset=True) == {"sync_teams": True}


def test_response_serializes_sync_teams():
    resp = GitHubInstanceResponse(
        id="gh-1",
        name="GitHub.com",
        url=_URL,
        oidc_audience="dependency-control",
        sync_teams=True,
        created_at=datetime.now(timezone.utc),
        created_by="user-1",
    )
    assert resp.model_dump()["sync_teams"] is True
