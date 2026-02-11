"""Tests for GitHub models (GitHubInstance, GitHubOIDCPayload)."""

from app.models.github_instance import GitHubInstance
from app.models.github_api import GitHubOIDCPayload


class TestGitHubInstanceModel:
    def test_minimal_valid_instance(self):
        instance = GitHubInstance(
            name="GitHub.com",
            url="https://token.actions.githubusercontent.com",
            created_by="admin",
        )
        assert instance.name == "GitHub.com"
        assert instance.url == "https://token.actions.githubusercontent.com"

    def test_defaults(self):
        instance = GitHubInstance(
            name="Test",
            url="https://token.actions.githubusercontent.com",
            created_by="admin",
        )
        assert instance.is_active is True
        assert instance.auto_create_projects is False
        assert instance.oidc_audience is None
        assert instance.github_url is None
        assert instance.description is None
        assert instance.last_modified_at is None

    def test_id_auto_generated(self):
        instance = GitHubInstance(
            name="Test",
            url="https://token.actions.githubusercontent.com",
            created_by="admin",
        )
        assert instance.id is not None
        assert len(instance.id) > 0

    def test_unique_ids(self):
        a = GitHubInstance(name="A", url="https://a.com", created_by="admin")
        b = GitHubInstance(name="B", url="https://b.com", created_by="admin")
        assert a.id != b.id

    def test_serialization_alias(self):
        instance = GitHubInstance(
            name="Test",
            url="https://token.actions.githubusercontent.com",
            created_by="admin",
        )
        data = instance.model_dump(by_alias=True)
        assert "_id" in data
        assert data["_id"] == instance.id

    def test_validation_alias(self):
        """Should accept _id from MongoDB documents."""
        instance = GitHubInstance(
            _id="custom-id",
            name="Test",
            url="https://token.actions.githubusercontent.com",
            created_by="admin",
        )
        assert instance.id == "custom-id"

    def test_optional_fields(self):
        instance = GitHubInstance(
            name="Full Instance",
            url="https://token.actions.githubusercontent.com",
            github_url="https://github.com",
            description="Main GitHub",
            oidc_audience="dependency-control",
            auto_create_projects=True,
            is_active=False,
            created_by="admin",
        )
        assert instance.github_url == "https://github.com"
        assert instance.description == "Main GitHub"
        assert instance.oidc_audience == "dependency-control"
        assert instance.auto_create_projects is True
        assert instance.is_active is False


class TestGitHubOIDCPayloadModel:
    def test_minimal_valid_payload(self):
        payload = GitHubOIDCPayload(
            repository_id="123456",
            repository="owner/repo",
            repository_owner="owner",
            actor="user",
        )
        assert payload.repository_id == "123456"
        assert payload.repository == "owner/repo"
        assert payload.repository_owner == "owner"
        assert payload.actor == "user"

    def test_optional_fields_default_none(self):
        payload = GitHubOIDCPayload(
            repository_id="1",
            repository="o/r",
            repository_owner="o",
            actor="u",
        )
        assert payload.ref is None
        assert payload.sha is None
        assert payload.workflow is None
        assert payload.run_id is None
        assert payload.event_name is None

    def test_with_all_fields(self):
        payload = GitHubOIDCPayload(
            repository_id="123",
            repository="org/repo",
            repository_owner="org",
            actor="developer",
            ref="refs/heads/main",
            sha="abc123",
            workflow="CI",
            run_id="9876",
            event_name="push",
        )
        assert payload.ref == "refs/heads/main"
        assert payload.sha == "abc123"
        assert payload.workflow == "CI"
        assert payload.run_id == "9876"
        assert payload.event_name == "push"

    def test_extra_claims_ignored(self):
        """GitHubOIDCPayload uses extra='ignore' to handle unknown JWT claims."""
        payload = GitHubOIDCPayload(
            repository_id="1",
            repository="o/r",
            repository_owner="o",
            actor="u",
            iss="https://token.actions.githubusercontent.com",
            sub="repo:o/r:ref:refs/heads/main",
            aud="dependency-control",
            unknown_field="should-be-ignored",
        )
        assert payload.repository_id == "1"
        assert not hasattr(payload, "iss")
        assert not hasattr(payload, "unknown_field")


class TestProjectGitHubFields:
    """Test that Project model accepts the new GitHub fields."""

    def test_project_with_github_fields(self):
        from app.models.project import Project

        project = Project(
            name="owner/repo",
            owner_id="user-1",
            github_instance_id="gh-inst-1",
            github_repository_id="123456",
            github_repository_path="owner/repo",
        )
        assert project.github_instance_id == "gh-inst-1"
        assert project.github_repository_id == "123456"
        assert project.github_repository_path == "owner/repo"

    def test_project_github_fields_default_none(self):
        from app.models.project import Project

        project = Project(name="test", owner_id="user-1")
        assert project.github_instance_id is None
        assert project.github_repository_id is None
        assert project.github_repository_path is None
