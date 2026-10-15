from app.models.github_api import GitHubOIDCPayload
from app.models.github_instance import GitHubInstance


def make_github_instance(
    id="test-github-instance-id",
    name="Test GitHub",
    url="https://token.actions.githubusercontent.com",
    github_url="https://github.com",
    oidc_audience="dependency-control",
    is_active=True,
    auto_create_projects=True,
    created_by="admin",
    **kwargs,
):
    return GitHubInstance(
        id=id,
        name=name,
        url=url,
        github_url=github_url,
        oidc_audience=oidc_audience,
        is_active=is_active,
        auto_create_projects=auto_create_projects,
        created_by=created_by,
        **kwargs,
    )


def github_instance_a():
    return make_github_instance(
        id="gh-instance-a-id",
        name="GitHub.com",
        url="https://token.actions.githubusercontent.com",
    )


def github_instance_b():
    return make_github_instance(
        id="gh-instance-b-id",
        name="GitHub Enterprise",
        url="https://github.corp.example.com/_services/token",
        github_url="https://github.corp.example.com",
        auto_create_projects=False,
    )


def make_github_oidc_payload(**kwargs):
    defaults = {
        "repository_id": "123456",
        "repository": "owner/repo",
        "repository_owner": "owner",
        "actor": "github-user",
    }
    defaults.update(kwargs)
    return GitHubOIDCPayload(**defaults)
