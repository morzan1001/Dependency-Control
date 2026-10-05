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
        token_configured=False,
    )
    assert resp.model_dump()["sync_teams"] is True


_GHES_URL = "https://github.corp.example.com/_services/token"


def _create(**overrides):
    fields = {"name": "GitHub.com", "url": _URL, "oidc_audience": "dependency-control", **overrides}
    return GitHubInstanceCreate(**fields)


@pytest.mark.parametrize("url", [_URL, f"{_URL}/"])
def test_create_refuses_auto_create_on_the_shared_issuer_without_an_owner_list(url):
    with pytest.raises(ValidationError, match="allowed owner"):
        _create(url=url, auto_create_projects=True)


def test_create_allows_auto_create_on_the_shared_issuer_with_an_owner_list():
    schema = _create(auto_create_projects=True, allowed_owner_ids=["111"])
    assert schema.allowed_owner_ids == ["111"]


def test_create_allows_the_shared_issuer_without_a_list_when_auto_create_is_off():
    assert _create().allowed_owner_ids == []


@pytest.mark.parametrize("url", [_GHES_URL, f"{_URL}/acme-enterprise"])
def test_create_leaves_the_list_optional_for_single_tenant_issuers(url):
    assert _create(url=url, auto_create_projects=True).auto_create_projects is True


@pytest.mark.parametrize("owner_id", ["acme", "", " 111", "1e3", "٣"])
def test_create_refuses_an_owner_id_that_is_not_numeric(owner_id):
    """The claim compared is repository_owner_id; a login on the list would silently admit nobody."""
    with pytest.raises(ValidationError, match="numeric"):
        _create(allowed_owner_ids=[owner_id])


def test_update_omits_the_owner_list_when_unset():
    assert "allowed_owner_ids" not in GitHubInstanceUpdate(name="renamed").model_dump(exclude_unset=True)


def test_update_carries_an_emptied_owner_list():
    assert GitHubInstanceUpdate(allowed_owner_ids=[]).model_dump(exclude_unset=True) == {"allowed_owner_ids": []}


def test_update_refuses_a_null_owner_list():
    """A stored null would stop the instance document from loading at all."""
    with pytest.raises(ValidationError):
        GitHubInstanceUpdate(allowed_owner_ids=None)


def test_update_refuses_an_owner_id_that_is_not_numeric():
    with pytest.raises(ValidationError, match="numeric"):
        GitHubInstanceUpdate(allowed_owner_ids=["acme"])


def test_response_serializes_the_owner_list():
    resp = GitHubInstanceResponse(
        id="gh-1",
        name="GitHub.com",
        url=_URL,
        allowed_owner_ids=["111"],
        created_at=datetime.now(timezone.utc),
        created_by="user-1",
        token_configured=False,
    )
    assert resp.model_dump()["allowed_owner_ids"] == ["111"]
