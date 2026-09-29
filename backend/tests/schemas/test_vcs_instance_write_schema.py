"""An instance write stores what it validates: a null in a field the stored instance requires fails
every later read of it, and a null or padded audience makes every CI token fail the audience check."""

import pytest
from pydantic import ValidationError

from app.schemas.github_instance import GitHubInstanceCreate, GitHubInstanceUpdate
from app.schemas.gitlab_instance import GitLabInstanceCreate, GitLabInstanceUpdate

_REQUIRED_IN_STORAGE = {
    GitHubInstanceUpdate: ("name", "url", "is_active", "oidc_audience", "auto_create_projects", "sync_teams"),
    GitLabInstanceUpdate: (
        "name",
        "url",
        "is_active",
        "is_default",
        "oidc_audience",
        "auto_create_projects",
        "sync_teams",
        "team_sync_depth",
    ),
}
_CLEARABLE = {
    GitHubInstanceUpdate: ("description", "github_url", "access_token"),
    GitLabInstanceUpdate: ("description", "access_token"),
}


@pytest.mark.parametrize(
    ("schema", "field"), [(schema, field) for schema, fields in _REQUIRED_IN_STORAGE.items() for field in fields]
)
def test_an_update_cannot_write_null_into_a_field_the_stored_instance_requires(schema, field):
    with pytest.raises(ValidationError):
        schema(**{field: None})


@pytest.mark.parametrize(
    ("schema", "field"), [(schema, field) for schema, fields in _CLEARABLE.items() for field in fields]
)
def test_an_update_can_still_clear_a_nullable_field(schema, field):
    assert schema(**{field: None}).model_dump(exclude_unset=True) == {field: None}


@pytest.mark.parametrize("schema", [GitHubInstanceUpdate, GitLabInstanceUpdate])
def test_an_update_stores_the_trimmed_audience(schema):
    assert schema(oidc_audience=" dependency-control\n").oidc_audience == "dependency-control"


def test_a_create_stores_the_trimmed_audience():
    github = GitHubInstanceCreate(name="gh", url="https://gh.example", oidc_audience=" aud ")
    gitlab = GitLabInstanceCreate(name="gl", url="https://gl.example", oidc_audience="aud ")

    assert (github.oidc_audience, gitlab.oidc_audience) == ("aud", "aud")
