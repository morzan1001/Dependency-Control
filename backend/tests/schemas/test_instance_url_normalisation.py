"""The issuer lookup strips a trailing slash, so every write has to store the URL without one."""

import pytest

from app.schemas.github_instance import GitHubInstanceCreate, GitHubInstanceUpdate
from app.schemas.gitlab_instance import GitLabInstanceCreate, GitLabInstanceUpdate

_BARE = "https://gitlab.example.test"


@pytest.mark.parametrize(
    "build",
    [
        lambda url: GitLabInstanceCreate(name="gl", url=url, oidc_audience="dc"),
        lambda url: GitLabInstanceUpdate(url=url),
        lambda url: GitHubInstanceCreate(name="gh", url=url, oidc_audience="dc"),
        lambda url: GitHubInstanceUpdate(url=url),
    ],
    ids=["gitlab create", "gitlab update", "github create", "github update"],
)
def test_an_inbound_url_loses_its_trailing_slash(build):
    assert build(f"{_BARE}/").url == _BARE
