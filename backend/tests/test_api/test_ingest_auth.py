"""Tests for the get_project_for_ingest authentication flow."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.system import SystemSettings
from tests.mocks.github import make_github_oidc_payload
from tests.mocks.gitlab import make_oidc_payload
from tests.mocks.mongodb import create_mock_collection, create_mock_db


def _make_system_settings(**kwargs):
    """Create SystemSettings with gitlab enabled by default."""
    defaults = {"gitlab_integration_enabled": True}
    defaults.update(kwargs)
    return SystemSettings(**defaults)


class TestIngestNoCredentials:
    def test_raises_401_when_no_auth(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()
        settings = _make_system_settings()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key=None,
                    oidc_token=None,
                    db=db,
                    settings=settings,
                )
            )
        assert exc_info.value.status_code == 401


class TestIngestApiKey:
    def test_invalid_format_raises_403(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()
        settings = _make_system_settings()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key="no-dot-separator",
                    oidc_token=None,
                    db=db,
                    settings=settings,
                )
            )
        assert exc_info.value.status_code == 403
        assert "format" in exc_info.value.detail.lower()

    def test_invalid_project_id_raises_403(self):
        from app.api.deps import get_project_for_ingest

        projects_coll = create_mock_collection(find_one=None)
        db = create_mock_db({"projects": projects_coll})
        settings = _make_system_settings()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key="bad-id.secret",
                    oidc_token=None,
                    db=db,
                    settings=settings,
                )
            )
        assert exc_info.value.status_code == 403

    def test_valid_api_key_returns_project(self):
        from app.api.deps import get_project_for_ingest

        project_doc = {
            "_id": "proj-1",
            "name": "Test Project",
            "owner_id": "user-1",
            "api_key_hash": "hashed-secret",
        }
        projects_coll = create_mock_collection(find_one=project_doc)
        db = create_mock_db({"projects": projects_coll})
        settings = _make_system_settings()

        with patch("app.api.deps.security.verify_password", return_value=True):
            result = asyncio.run(
                get_project_for_ingest(
                    x_api_key="proj-1.my-secret",
                    oidc_token=None,
                    db=db,
                    settings=settings,
                )
            )

        assert result.name == "Test Project"
        assert result.id == "proj-1"


class TestIngestOidcBasicValidation:
    def test_raises_403_for_non_jwt_token(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()
        settings = _make_system_settings()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key=None,
                    oidc_token="not-a-jwt",
                    db=db,
                    settings=settings,
                )
            )
        assert exc_info.value.status_code == 403
        assert "JWT" in exc_info.value.detail


class TestIngestOidcInstanceRouting:
    """OIDC flow must extract issuer and route to the correct instance (GitLab or GitHub)."""

    def test_raises_403_when_no_matching_instance(self):
        from app.api.deps import get_project_for_ingest

        gitlab_instances_coll = create_mock_collection(find_one=None)
        github_instances_coll = create_mock_collection(find_one=None)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
            }
        )
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://unknown-provider.com"}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )
            assert exc_info.value.status_code == 403
            assert "No CI/CD instance configured" in exc_info.value.detail

    def test_raises_403_when_instance_inactive(self):
        from app.api.deps import get_project_for_ingest

        instance_doc = {
            "_id": "inst-1",
            "name": "Inactive",
            "url": "https://gitlab.com",
            "is_active": False,
            "created_by": "admin",
        }
        gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
        db = create_mock_db({"gitlab_instances": gitlab_instances_coll})
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab.com"}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )
            assert exc_info.value.status_code == 403
            assert "not active" in exc_info.value.detail.lower()

    def test_raises_403_when_token_missing_issuer(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )
            assert exc_info.value.status_code == 403
            assert "issuer" in exc_info.value.detail.lower()

    def test_raises_403_on_malformed_token(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.side_effect = Exception("Cannot decode")

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )
            assert exc_info.value.status_code == 403

    def test_raises_403_when_oidc_validation_fails(self):
        from app.api.deps import get_project_for_ingest

        instance_doc = {
            "_id": "inst-1",
            "name": "GL",
            "url": "https://gitlab.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
        }
        gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
            }
        )
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab.com"}

            with patch("app.api.deps.GitLabService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(return_value=None)
                MockService.return_value = mock_svc

                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        get_project_for_ingest(
                            x_api_key=None,
                            oidc_token="a.b.c",
                            db=db,
                            settings=settings,
                        )
                    )
                assert exc_info.value.status_code == 403


class TestIngestOidcProjectLookup:
    """After OIDC validation, should find project via composite key."""

    def _setup_oidc_mocks(self, instance_doc, project_doc, oidc_payload):
        """Helper to set up the common OIDC mocking chain."""
        gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
        projects_coll = create_mock_collection(find_one=project_doc)
        users_coll = create_mock_collection(find_one=None)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )
        return db

    def test_returns_existing_project_via_composite_key(self):
        from app.api.deps import get_project_for_ingest

        instance_doc = {
            "_id": "inst-a",
            "name": "A",
            "url": "https://gitlab-a.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
            "sync_teams": False,
        }
        project_doc = {
            "_id": "proj-1",
            "name": "My Project",
            "owner_id": "user-1",
            "gitlab_instance_id": "inst-a",
            "gitlab_project_id": 42,
        }

        db = self._setup_oidc_mocks(instance_doc, project_doc, None)
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab-a.com"}

            with patch("app.api.deps.GitLabService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_oidc_payload(
                        project_id="42",
                        project_path="group/my-project",
                        user_email="dev@test.com",
                    )
                )
                MockService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )

        assert result.name == "My Project"
        assert result.id == "proj-1"

    def test_auto_creates_project_when_enabled(self):
        from app.api.deps import get_project_for_ingest

        instance_doc = {
            "_id": "inst-a",
            "name": "A",
            "url": "https://gitlab-a.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
            "auto_create_projects": True,
            "sync_teams": False,
        }

        admin_doc = {"_id": "admin-id", "username": "admin", "is_superuser": True}

        gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        users_coll = create_mock_collection(find_one=admin_doc)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )
        settings = _make_system_settings()

        # find_one_and_update returns the newly created document (simulates upsert insert)
        def fake_find_or_create(filter_query, update, **kwargs):
            return update.get("$setOnInsert", {})

        projects_coll.find_one_and_update = AsyncMock(side_effect=fake_find_or_create)

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab-a.com"}

            with patch("app.api.deps.GitLabService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_oidc_payload(
                        project_id="99",
                        project_path="group/new-project",
                        user_email="dev@test.com",
                    )
                )
                MockService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )

        assert result.name == "group/new-project"
        assert result.gitlab_instance_id == "inst-a"
        assert result.gitlab_project_id == 99
        assert result.active_analyzers == settings.default_active_analyzers
        projects_coll.find_one_and_update.assert_called_once()

    def test_raises_404_when_auto_create_disabled(self):
        from app.api.deps import get_project_for_ingest

        instance_doc = {
            "_id": "inst-b",
            "name": "B",
            "url": "https://gitlab-b.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
            "auto_create_projects": False,
            "sync_teams": False,
        }

        gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
            }
        )
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab-b.com"}

            with patch("app.api.deps.GitLabService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_oidc_payload(
                        project_id="99",
                        project_path="group/proj",
                    )
                )
                MockService.return_value = mock_svc

                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        get_project_for_ingest(
                            x_api_key=None,
                            oidc_token="a.b.c",
                            db=db,
                            settings=settings,
                        )
                    )
                assert exc_info.value.status_code == 404
                assert "auto-creation is disabled" in exc_info.value.detail

    def test_same_project_id_different_instances_returns_correct_project(self):
        from app.api.deps import get_project_for_ingest

        instance_a_doc = {
            "_id": "inst-a",
            "name": "A",
            "url": "https://gitlab-a.com",
            "access_token": "tok-a",
            "is_active": True,
            "created_by": "admin",
            "sync_teams": False,
        }
        project_a_doc = {
            "_id": "proj-a",
            "name": "Project on A",
            "owner_id": "u1",
            "gitlab_instance_id": "inst-a",
            "gitlab_project_id": 42,
        }

        instance_b_doc = {
            "_id": "inst-b",
            "name": "B",
            "url": "https://gitlab-b.com",
            "access_token": "tok-b",
            "is_active": True,
            "created_by": "admin",
            "sync_teams": False,
        }
        project_b_doc = {
            "_id": "proj-b",
            "name": "Project on B",
            "owner_id": "u1",
            "gitlab_instance_id": "inst-b",
            "gitlab_project_id": 42,
        }

        settings = _make_system_settings()
        results = []

        for instance_doc, project_doc, issuer in [
            (instance_a_doc, project_a_doc, "https://gitlab-a.com"),
            (instance_b_doc, project_b_doc, "https://gitlab-b.com"),
        ]:
            gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
            projects_coll = create_mock_collection(find_one=project_doc)
            db = create_mock_db(
                {
                    "gitlab_instances": gitlab_instances_coll,
                    "projects": projects_coll,
                }
            )

            with patch("jose.jwt.get_unverified_claims") as mock_claims:
                mock_claims.return_value = {"iss": issuer}

                with patch("app.api.deps.GitLabService") as MockService:
                    mock_svc = MagicMock()
                    mock_svc.validate_oidc_token = AsyncMock(
                        return_value=make_oidc_payload(
                            project_id="42",
                            project_path="group/proj",
                        )
                    )
                    MockService.return_value = mock_svc

                    result = asyncio.run(
                        get_project_for_ingest(
                            x_api_key=None,
                            oidc_token="a.b.c",
                            db=db,
                            settings=settings,
                        )
                    )
                    results.append(result)

        assert results[0].name == "Project on A"
        assert results[1].name == "Project on B"
        assert results[0].id != results[1].id


class TestIngestGitHubOidcInstanceRouting:
    """OIDC flow must route to GitHub instance when issuer matches."""

    def test_raises_403_when_github_instance_inactive(self):
        from app.api.deps import get_project_for_ingest

        github_instance_doc = {
            "_id": "gh-inst-1",
            "name": "GitHub Inactive",
            "url": "https://token.actions.githubusercontent.com",
            "is_active": False,
            "created_by": "admin",
        }
        gitlab_instances_coll = create_mock_collection(find_one=None)
        github_instances_coll = create_mock_collection(find_one=github_instance_doc)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
            }
        )
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )
            assert exc_info.value.status_code == 403
            assert "not active" in exc_info.value.detail.lower()

    def test_raises_403_when_github_oidc_validation_fails(self):
        from app.api.deps import get_project_for_ingest

        github_instance_doc = {
            "_id": "gh-inst-1",
            "name": "GitHub.com",
            "url": "https://token.actions.githubusercontent.com",
            "is_active": True,
            "created_by": "admin",
        }
        gitlab_instances_coll = create_mock_collection(find_one=None)
        github_instances_coll = create_mock_collection(find_one=github_instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
            }
        )
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with patch("app.services.github.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(return_value=None)
                MockService.return_value = mock_svc

                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        get_project_for_ingest(
                            x_api_key=None,
                            oidc_token="a.b.c",
                            db=db,
                            settings=settings,
                        )
                    )
                assert exc_info.value.status_code == 403
                assert "GitHub" in exc_info.value.detail


class TestIngestGitHubOidcProjectLookup:
    """After GitHub OIDC validation, should find project via composite key."""

    def _setup_github_mocks(self, github_instance_doc, project_doc, admin_doc=None):
        """Helper to set up the common GitHub OIDC mocking chain."""
        gitlab_instances_coll = create_mock_collection(find_one=None)
        github_instances_coll = create_mock_collection(find_one=github_instance_doc)
        projects_coll = create_mock_collection(find_one=project_doc)
        users_coll = create_mock_collection(find_one=admin_doc)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )
        return db, projects_coll

    def test_returns_existing_project_via_composite_key(self):
        from app.api.deps import get_project_for_ingest

        github_instance_doc = {
            "_id": "gh-inst-a",
            "name": "GitHub.com",
            "url": "https://token.actions.githubusercontent.com",
            "is_active": True,
            "created_by": "admin",
        }
        project_doc = {
            "_id": "proj-gh-1",
            "name": "owner/my-repo",
            "owner_id": "user-1",
            "github_instance_id": "gh-inst-a",
            "github_repository_id": "123456",
            "github_repository_path": "owner/my-repo",
        }

        db, _ = self._setup_github_mocks(github_instance_doc, project_doc)
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with patch("app.services.github.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_github_oidc_payload(
                        repository_id="123456",
                        repository="owner/my-repo",
                        actor="developer",
                    )
                )
                MockService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )

        assert result.name == "owner/my-repo"
        assert result.id == "proj-gh-1"

    def test_auto_creates_project_when_enabled(self):
        from app.api.deps import get_project_for_ingest

        github_instance_doc = {
            "_id": "gh-inst-a",
            "name": "GitHub.com",
            "url": "https://token.actions.githubusercontent.com",
            "is_active": True,
            "created_by": "admin",
            "auto_create_projects": True,
        }
        admin_doc = {"_id": "admin-id", "username": "admin", "is_superuser": True}

        gitlab_instances_coll = create_mock_collection(find_one=None)
        github_instances_coll = create_mock_collection(find_one=github_instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        users_coll = create_mock_collection(find_one=admin_doc)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )
        settings = _make_system_settings()

        # find_one_and_update returns the newly created document (simulates upsert insert)
        def fake_find_or_create(filter_query, update, **kwargs):
            return update.get("$setOnInsert", {})

        projects_coll.find_one_and_update = AsyncMock(side_effect=fake_find_or_create)

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with patch("app.services.github.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_github_oidc_payload(
                        repository_id="789",
                        repository="org/new-repo",
                        actor="developer",
                    )
                )
                MockService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )

        assert result.name == "org/new-repo"
        assert result.github_instance_id == "gh-inst-a"
        assert result.github_repository_id == "789"
        assert result.github_repository_path == "org/new-repo"
        assert result.active_analyzers == settings.default_active_analyzers
        projects_coll.find_one_and_update.assert_called_once()

    def test_raises_404_when_auto_create_disabled(self):
        from app.api.deps import get_project_for_ingest

        github_instance_doc = {
            "_id": "gh-inst-b",
            "name": "GitHub Enterprise",
            "url": "https://github.corp.example.com/_services/token",
            "is_active": True,
            "created_by": "admin",
            "auto_create_projects": False,
        }

        db, _ = self._setup_github_mocks(github_instance_doc, None)
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://github.corp.example.com/_services/token"}

            with patch("app.services.github.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_github_oidc_payload(
                        repository_id="999",
                        repository="org/repo",
                    )
                )
                MockService.return_value = mock_svc

                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        get_project_for_ingest(
                            x_api_key=None,
                            oidc_token="a.b.c",
                            db=db,
                            settings=settings,
                        )
                    )
                assert exc_info.value.status_code == 404
                assert "auto-creation is disabled" in exc_info.value.detail

    def test_gitlab_takes_priority_over_github(self):
        from app.api.deps import get_project_for_ingest

        gitlab_instance_doc = {
            "_id": "gl-inst",
            "name": "GitLab",
            "url": "https://gitlab.com",
            "access_token": "tok",
            "is_active": True,
            "created_by": "admin",
            "sync_teams": False,
        }
        project_doc = {
            "_id": "proj-gl",
            "name": "GL Project",
            "owner_id": "u1",
            "gitlab_instance_id": "gl-inst",
            "gitlab_project_id": 42,
        }

        gitlab_instances_coll = create_mock_collection(find_one=gitlab_instance_doc)
        github_instances_coll = create_mock_collection(find_one=None)
        projects_coll = create_mock_collection(find_one=project_doc)
        db = create_mock_db(
            {
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
            }
        )
        settings = _make_system_settings()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab.com"}

            with patch("app.api.deps.GitLabService") as MockGitLabService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_oidc_payload(project_id="42", project_path="g/p")
                )
                MockGitLabService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                        settings=settings,
                    )
                )

        assert result.name == "GL Project"
        assert result.id == "proj-gl"


_TEAM_SYNC_INSTANCE = {
    "_id": "gh-inst-a",
    "name": "GitHub.com",
    "url": "https://token.actions.githubusercontent.com",
    "is_active": True,
    "created_by": "admin",
    "access_token": "ghp-secret",
}
_TEAM_SYNC_PROJECT = {
    "_id": "proj-gh-1",
    "name": "acme/widgets",
    "github_instance_id": "gh-inst-a",
    "github_repository_id": "123456",
    "github_repository_path": "acme/widgets",
}


class TestIngestGitHubTeamSync:
    """GitHub OIDC ingest assigns the repository's team when the instance opts in."""

    def _run(self, instance_doc, sync_result, project_doc=None, **payload_overrides):
        from app.api.deps import get_project_for_ingest
        from app.services.github import GitHubTeamSyncResult

        projects_coll = create_mock_collection(find_one=project_doc)
        projects_coll.find_one_and_update = AsyncMock(side_effect=lambda _q, update, **_kw: update["$setOnInsert"])
        db = create_mock_db(
            {
                "gitlab_instances": create_mock_collection(find_one=None),
                "github_instances": create_mock_collection(find_one=instance_doc),
                "projects": projects_coll,
                "users": create_mock_collection(find_one=None),
            }
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}
            with patch("app.services.github.GitHubService") as MockService:
                mock_svc = MagicMock()
                payload = {"repository_id": "123456", "repository": "acme/widgets", "repository_owner": "acme"}
                payload.update(payload_overrides)
                mock_svc.validate_oidc_token = AsyncMock(return_value=make_github_oidc_payload(**payload))
                mock_svc.sync_team_from_github = AsyncMock(return_value=GitHubTeamSyncResult(*sync_result))
                MockService.return_value = mock_svc

                asyncio.run(
                    get_project_for_ingest(x_api_key=None, oidc_token="a.b.c", db=db, settings=_make_system_settings())
                )
        return mock_svc, projects_coll, db

    def test_sync_is_not_called_when_the_instance_has_it_off(self):
        mock_svc, projects_coll, _ = self._run(
            {**_TEAM_SYNC_INSTANCE, "sync_teams": False}, ("t-9", 1), project_doc=_TEAM_SYNC_PROJECT
        )
        mock_svc.sync_team_from_github.assert_not_called()
        projects_coll.update_one.assert_not_called()

    def test_sync_is_not_called_on_auto_create_when_the_instance_has_it_off(self):
        instance = {**_TEAM_SYNC_INSTANCE, "sync_teams": False, "auto_create_projects": True}
        mock_svc, projects_coll, _ = self._run(instance, ("t-9", 1))
        mock_svc.sync_team_from_github.assert_not_called()
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_id"] is None
        assert inserted["github_team_candidates"] is None

    def test_the_owning_org_comes_from_the_token(self):
        mock_svc, _, db = self._run(
            {**_TEAM_SYNC_INSTANCE, "sync_teams": True}, ("t-9", 1), project_doc=_TEAM_SYNC_PROJECT
        )
        mock_svc.sync_team_from_github.assert_awaited_once_with(db, "acme", "acme/widgets")

    def test_the_org_is_the_repository_owner_claim_not_the_path_prefix(self):
        """Pins which claim sources the org; the two agree in real tokens, so nothing else would catch a swap."""
        mock_svc, _, db = self._run(
            {**_TEAM_SYNC_INSTANCE, "sync_teams": True},
            ("t-9", 1),
            project_doc=_TEAM_SYNC_PROJECT,
            repository_owner="acme-org",
        )
        mock_svc.sync_team_from_github.assert_awaited_once_with(db, "acme-org", "acme/widgets")

    def test_the_team_and_the_candidate_count_are_written_to_the_project(self):
        _, projects_coll, _ = self._run(
            {**_TEAM_SYNC_INSTANCE, "sync_teams": True}, ("t-9", 3), project_doc=_TEAM_SYNC_PROJECT
        )
        assert projects_coll.update_one.await_args.args[0] == {"_id": "proj-gh-1"}
        update = projects_coll.update_one.await_args.args[1]["$set"]
        assert update["team_id"] == "t-9"
        assert update["team_source"] == "github"
        assert update["github_team_candidates"] == 3

    def test_an_auto_created_project_carries_the_synced_team(self):
        instance = {**_TEAM_SYNC_INSTANCE, "sync_teams": True, "auto_create_projects": True}
        mock_svc, projects_coll, db = self._run(instance, ("t-9", 3), repository_owner="acme-org")
        # The auto-create call site sources the org from the same claim as the existing-project one.
        mock_svc.sync_team_from_github.assert_awaited_once_with(db, "acme-org", "acme/widgets")
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_id"] == "t-9"
        assert inserted["team_source"] == "github"
        assert inserted["github_team_candidates"] == 3
        # The model no longer fabricates the list from the scalar; phase 4 makes this writer set it.
        assert inserted["team_ids"] == []

    def test_an_auto_created_project_without_a_team_is_still_created(self):
        instance = {**_TEAM_SYNC_INSTANCE, "sync_teams": True, "auto_create_projects": True}
        _, projects_coll, _ = self._run(instance, (None, 0))
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_id"] is None
        assert inserted["team_source"] is None
        assert inserted["github_team_candidates"] == 0


_GITLAB_TEAM_SYNC_INSTANCE = {
    "_id": "gl-inst-a",
    "name": "GitLab.com",
    "url": "https://gitlab.com",
    "access_token": "glpat-secret",
    "is_active": True,
    "created_by": "admin",
}


class TestIngestGitLabTeamSync:
    """GitLab OIDC ingest assigns the project's team when the instance opts in."""

    def _run(self, instance_doc, team_id):
        from app.api.deps import get_project_for_ingest

        projects_coll = create_mock_collection(find_one=None)
        projects_coll.find_one_and_update = AsyncMock(side_effect=lambda _q, update, **_kw: update["$setOnInsert"])
        db = create_mock_db(
            {
                "gitlab_instances": create_mock_collection(find_one=instance_doc),
                "github_instances": create_mock_collection(find_one=None),
                "projects": projects_coll,
                "users": create_mock_collection(find_one=None),
            }
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab.com"}
            with patch("app.api.deps.GitLabService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_oidc_payload(
                        project_id="99",
                        project_path="group/new-project",
                        user_email="dev@test.com",
                    )
                )
                mock_svc.get_project_details = AsyncMock(return_value={})
                mock_svc.sync_team_from_gitlab = AsyncMock(return_value=team_id)
                MockService.return_value = mock_svc

                asyncio.run(
                    get_project_for_ingest(x_api_key=None, oidc_token="a.b.c", db=db, settings=_make_system_settings())
                )
        return mock_svc, projects_coll, db

    def test_an_auto_created_project_carries_the_synced_team(self):
        instance = {**_GITLAB_TEAM_SYNC_INSTANCE, "sync_teams": True, "auto_create_projects": True}
        mock_svc, projects_coll, db = self._run(instance, "t-gl-1")
        mock_svc.sync_team_from_gitlab.assert_awaited_once_with(db, 99, "group/new-project", gitlab_project_data={})
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_id"] == "t-gl-1"
        assert inserted["team_source"] == "gitlab"
        # The model no longer fabricates the list from the scalar; phase 4 makes this writer set it.
        assert inserted["team_ids"] == []
