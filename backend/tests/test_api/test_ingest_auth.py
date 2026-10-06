"""Tests for the get_project_for_ingest authentication flow."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from jose import JWTError

from app.core.constants import MAX_PROJECT_TEAMS, TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from app.models.system import SystemSettings
from tests.mocks.github import make_github_oidc_payload
from tests.mocks.gitlab import make_oidc_payload
from tests.mocks.mongodb import create_mock_collection, create_mock_db


class TestIngestNoCredentials:
    def test_raises_401_when_no_auth(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key=None,
                    oidc_token=None,
                    db=db,
                )
            )
        assert exc_info.value.status_code == 401


class TestIngestApiKey:
    def test_invalid_format_raises_403(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key="no-dot-separator",
                    oidc_token=None,
                    db=db,
                )
            )
        assert exc_info.value.status_code == 403
        assert "format" in exc_info.value.detail.lower()

    def test_invalid_project_id_raises_403(self):
        from app.api.deps import get_project_for_ingest

        projects_coll = create_mock_collection(find_one=None)
        db = create_mock_db({"projects": projects_coll})

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key="bad-id.secret",
                    oidc_token=None,
                    db=db,
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

        with patch("app.api.deps.security.verify_password", return_value=True):
            result = asyncio.run(
                get_project_for_ingest(
                    x_api_key="proj-1.my-secret",
                    oidc_token=None,
                    db=db,
                )
            )

        assert result.name == "Test Project"
        assert result.id == "proj-1"


class TestIngestOidcBasicValidation:
    def test_raises_403_for_non_jwt_token(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                get_project_for_ingest(
                    x_api_key=None,
                    oidc_token="not-a-jwt",
                    db=db,
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
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
            }
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://unknown-provider.com"}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
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

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://gitlab.com"}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                    )
                )
            assert exc_info.value.status_code == 403
            assert "not active" in exc_info.value.detail.lower()

    def test_raises_403_when_token_missing_issuer(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                    )
                )
            assert exc_info.value.status_code == 403
            assert "issuer" in exc_info.value.detail.lower()

    def test_raises_403_on_malformed_token(self):
        from app.api.deps import get_project_for_ingest

        db = MagicMock()

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.side_effect = JWTError("Cannot decode")

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
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
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
            }
        )

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
        return create_mock_db(
            {
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )

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
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )

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
                    )
                )

        assert result.name == "group/new-project"
        assert result.gitlab_instance_id == "inst-a"
        assert result.gitlab_project_id == 99
        assert result.active_analyzers == SystemSettings().default_active_analyzers
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
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "projects": projects_coll,
            }
        )

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

        results = []

        for instance_doc, project_doc, issuer in [
            (instance_a_doc, project_a_doc, "https://gitlab-a.com"),
            (instance_b_doc, project_b_doc, "https://gitlab-b.com"),
        ]:
            gitlab_instances_coll = create_mock_collection(find_one=instance_doc)
            projects_coll = create_mock_collection(find_one=project_doc)
            db = create_mock_db(
                {
                    "system_settings": create_mock_collection(find_one=None),
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
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
            }
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
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
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
            }
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with patch("app.api.deps.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(return_value=None)
                MockService.return_value = mock_svc

                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        get_project_for_ingest(
                            x_api_key=None,
                            oidc_token="a.b.c",
                            db=db,
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
                "system_settings": create_mock_collection(find_one=None),
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

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with patch("app.api.deps.GitHubService") as MockService:
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
            "allowed_owner_ids": ["111"],
        }
        admin_doc = {"_id": "admin-id", "username": "admin", "is_superuser": True}

        gitlab_instances_coll = create_mock_collection(find_one=None)
        github_instances_coll = create_mock_collection(find_one=github_instance_doc)
        projects_coll = create_mock_collection(find_one=None)
        users_coll = create_mock_collection(find_one=admin_doc)
        db = create_mock_db(
            {
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
                "users": users_coll,
            }
        )

        # find_one_and_update returns the newly created document (simulates upsert insert)
        def fake_find_or_create(filter_query, update, **kwargs):
            return update.get("$setOnInsert", {})

        projects_coll.find_one_and_update = AsyncMock(side_effect=fake_find_or_create)

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}

            with patch("app.api.deps.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_github_oidc_payload(
                        repository_id="789",
                        repository="org/new-repo",
                        repository_owner_id="111",
                        actor="developer",
                    )
                )
                mock_svc.resolve_login = AsyncMock(return_value=None)
                MockService.return_value = mock_svc

                result = asyncio.run(
                    get_project_for_ingest(
                        x_api_key=None,
                        oidc_token="a.b.c",
                        db=db,
                    )
                )

        assert result.name == "org/new-repo"
        assert result.github_instance_id == "gh-inst-a"
        assert result.github_repository_id == "789"
        assert result.github_repository_path == "org/new-repo"
        assert result.active_analyzers == SystemSettings().default_active_analyzers
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

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://github.corp.example.com/_services/token"}

            with patch("app.api.deps.GitHubService") as MockService:
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
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": gitlab_instances_coll,
                "github_instances": github_instances_coll,
                "projects": projects_coll,
            }
        )

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
    "allowed_owner_ids": ["111"],
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

    def _run(self, instance_doc, sync_result, project_doc=None):
        from app.api.deps import get_project_for_ingest
        from app.models.team import TeamSyncResult

        projects_coll = create_mock_collection(find_one=project_doc)
        projects_coll.find_one_and_update = AsyncMock(side_effect=lambda _q, update, **_kw: update["$setOnInsert"])
        db = create_mock_db(
            {
                "system_settings": create_mock_collection(find_one=None),
                "gitlab_instances": create_mock_collection(find_one=None),
                "github_instances": create_mock_collection(find_one=instance_doc),
                "projects": projects_coll,
                "users": create_mock_collection(find_one=None),
            }
        )

        with patch("jose.jwt.get_unverified_claims") as mock_claims:
            mock_claims.return_value = {"iss": "https://token.actions.githubusercontent.com"}
            with patch("app.api.deps.GitHubService") as MockService:
                mock_svc = MagicMock()
                mock_svc.validate_oidc_token = AsyncMock(
                    return_value=make_github_oidc_payload(
                        repository_id="123456",
                        repository="acme/widgets",
                        repository_owner="acme",
                        repository_owner_id="111",
                    )
                )
                mock_svc.sync_team_from_github = AsyncMock(return_value=TeamSyncResult(sync_result))
                mock_svc.resolve_login = AsyncMock(return_value=None)
                MockService.return_value = mock_svc

                asyncio.run(get_project_for_ingest(x_api_key=None, oidc_token="a.b.c", db=db))
        return mock_svc, projects_coll, db

    def test_sync_is_not_called_when_the_instance_has_it_off(self):
        mock_svc, projects_coll, _ = self._run(
            {**_TEAM_SYNC_INSTANCE, "sync_teams": False}, ["t-9"], project_doc=_TEAM_SYNC_PROJECT
        )
        mock_svc.sync_team_from_github.assert_not_called()
        projects_coll.update_one.assert_not_called()

    def test_sync_is_not_called_on_auto_create_when_the_instance_has_it_off(self):
        instance = {**_TEAM_SYNC_INSTANCE, "sync_teams": False, "auto_create_projects": True}
        mock_svc, projects_coll, _ = self._run(instance, ["t-9"])
        mock_svc.sync_team_from_github.assert_not_called()
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_ids"] == []

    def test_the_repository_comes_from_the_token(self):
        mock_svc, _, db = self._run(
            {**_TEAM_SYNC_INSTANCE, "sync_teams": True}, ["t-9"], project_doc=_TEAM_SYNC_PROJECT
        )
        mock_svc.sync_team_from_github.assert_awaited_once_with(
            db, "acme/widgets", current_owner_ids=set(), owner_budget=MAX_PROJECT_TEAMS
        )

    def test_every_resolved_owner_is_written_to_the_project(self):
        """The guarded pipeline reaches the server: that is what keeps a manual co-owner and the
        other provider's entry out of this write."""
        from app.repositories.projects import replace_team_subset_pipeline

        _, projects_coll, _ = self._run(
            {**_TEAM_SYNC_INSTANCE, "sync_teams": True}, ["t-9", "t-4"], project_doc=_TEAM_SYNC_PROJECT
        )
        assert projects_coll.update_one.await_args.args[0] == {"_id": "proj-gh-1"}
        expected_source = team_source(TEAM_SOURCE_GITHUB, _TEAM_SYNC_INSTANCE["_id"])
        assert projects_coll.update_one.await_args.args[1] == replace_team_subset_pipeline(
            expected_source, ["t-4", "t-9"]
        )

    def test_an_auto_created_project_carries_every_synced_team(self):
        instance = {**_TEAM_SYNC_INSTANCE, "sync_teams": True, "auto_create_projects": True}
        mock_svc, projects_coll, db = self._run(instance, ["t-9", "t-4"])
        # A project being created has the whole cap to itself.
        mock_svc.sync_team_from_github.assert_awaited_once_with(db, "acme/widgets", current_owner_ids=set())
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_ids"] == ["t-4", "t-9"]
        expected_source = team_source(TEAM_SOURCE_GITHUB, _TEAM_SYNC_INSTANCE["_id"])
        assert inserted["team_sources"] == {"t-4": expected_source, "t-9": expected_source}

    def test_an_auto_created_project_without_a_team_is_still_created(self):
        instance = {**_TEAM_SYNC_INSTANCE, "sync_teams": True, "auto_create_projects": True}
        _, projects_coll, _ = self._run(instance, [])
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_ids"] == []
        assert inserted["team_sources"] == {}


_GITLAB_TEAM_SYNC_INSTANCE = {
    "_id": "gl-inst-a",
    "name": "GitLab.com",
    "url": "https://gitlab.com",
    "access_token": "glpat-secret",
    "is_active": True,
    "created_by": "admin",
    "allowed_namespaces": ["group"],
}


class TestIngestGitLabTeamSync:
    """GitLab OIDC ingest assigns the project's team when the instance opts in."""

    def _run(self, instance_doc, team_ids):
        from app.api.deps import get_project_for_ingest
        from app.models.team import TeamSyncResult

        projects_coll = create_mock_collection(find_one=None)
        projects_coll.find_one_and_update = AsyncMock(side_effect=lambda _q, update, **_kw: update["$setOnInsert"])
        db = create_mock_db(
            {
                "system_settings": create_mock_collection(find_one=None),
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
                mock_svc.sync_team_from_gitlab = AsyncMock(return_value=TeamSyncResult(team_ids))
                MockService.return_value = mock_svc

                asyncio.run(get_project_for_ingest(x_api_key=None, oidc_token="a.b.c", db=db))
        return mock_svc, projects_coll, db

    def test_an_auto_created_project_carries_the_synced_team(self):
        instance = {**_GITLAB_TEAM_SYNC_INSTANCE, "sync_teams": True, "auto_create_projects": True}
        mock_svc, projects_coll, db = self._run(instance, ["t-gl-1"])
        mock_svc.sync_team_from_gitlab.assert_awaited_once_with(db, 99, "group/new-project")
        inserted = projects_coll.find_one_and_update.await_args.args[1]["$setOnInsert"]
        assert inserted["team_ids"] == ["t-gl-1"]
        expected_source = team_source(TEAM_SOURCE_GITLAB, _GITLAB_TEAM_SYNC_INSTANCE["_id"])
        assert inserted["team_sources"] == {"t-gl-1": expected_source}


_GITHUB_COM_ISSUER = "https://token.actions.githubusercontent.com"
_GHES_ISSUER = "https://github.corp.example.com/_services/token"
_GITHUB_COM_INSTANCE = {
    "_id": "gh-inst-a",
    "name": "GitHub.com",
    "url": _GITHUB_COM_ISSUER,
    "is_active": True,
    "created_by": "admin",
    "sync_teams": True,
    "access_token": "ghp-secret",
}
_GITHUB_BOUND_PROJECT = {
    "_id": "proj-gh-1",
    "name": "acme/widgets",
    "github_instance_id": "gh-inst-a",
    "github_repository_id": "123456",
    "github_repository_path": "acme/widgets",
}


def _ingest_via_github(
    instance_doc,
    project_doc=None,
    issuer=_GITHUB_COM_ISSUER,
    *,
    any_user=None,
    actor_resolution=None,
    **payload_overrides,
):
    """Run a GitHub OIDC ingest; returns the outcome (project or HTTPException), projects and service mocks.

    ``any_user`` answers every users query, so a lookup by the actor's login would find it.
    """
    from app.api.deps import get_project_for_ingest
    from app.models.team import TeamSyncResult

    projects_coll = create_mock_collection(find_one=project_doc)
    projects_coll.find_one_and_update = AsyncMock(side_effect=lambda _q, update, **_kw: update["$setOnInsert"])
    db = create_mock_db(
        {
            "system_settings": create_mock_collection(find_one=None),
            "gitlab_instances": create_mock_collection(find_one=None),
            "github_instances": create_mock_collection(find_one=instance_doc),
            "projects": projects_coll,
            "users": create_mock_collection(find_one=any_user),
        }
    )
    payload = {
        "repository_id": "123456",
        "repository": "acme/widgets",
        "repository_owner": "acme",
        "repository_owner_id": "111",
        **payload_overrides,
    }
    with patch("jose.jwt.get_unverified_claims", return_value={"iss": issuer}):
        with patch("app.api.deps.GitHubService") as MockService:
            mock_svc = MagicMock()
            mock_svc.validate_oidc_token = AsyncMock(return_value=make_github_oidc_payload(**payload))
            mock_svc.sync_team_from_github = AsyncMock(return_value=TeamSyncResult([]))
            mock_svc.resolve_login = AsyncMock(return_value=actor_resolution)
            MockService.return_value = mock_svc
            try:
                outcome = asyncio.run(get_project_for_ingest(x_api_key=None, oidc_token="a.b.c", db=db))
            except HTTPException as exc:
                outcome = exc
    return outcome, projects_coll, mock_svc


class TestIngestGitHubOwnerAllowlist:
    """A github.com token is signed for every repository in the world, so the owner decides admission."""

    def test_a_foreign_owner_is_refused_before_the_project_lookup(self):
        instance = {**_GITHUB_COM_INSTANCE, "allowed_owner_ids": ["111"], "auto_create_projects": True}

        outcome, projects_coll, mock_svc = _ingest_via_github(
            instance, _GITHUB_BOUND_PROJECT, repository_owner="evil", repository_owner_id="999"
        )

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        assert "999" in outcome.detail
        projects_coll.find_one.assert_not_called()
        projects_coll.find_one_and_update.assert_not_called()
        mock_svc.sync_team_from_github.assert_not_called()

    def test_a_token_without_the_owner_id_claim_is_refused_when_a_list_is_set(self):
        instance = {**_GITHUB_COM_INSTANCE, "allowed_owner_ids": ["111"]}

        outcome, projects_coll, _ = _ingest_via_github(instance, _GITHUB_BOUND_PROJECT, repository_owner_id=None)

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        projects_coll.find_one.assert_not_called()

    def test_the_owner_login_alone_does_not_admit_a_token(self):
        """The login is renamable and re-registrable; only the numeric id is on the list."""
        instance = {**_GITHUB_COM_INSTANCE, "allowed_owner_ids": ["111"]}

        outcome, _, _ = _ingest_via_github(
            instance, _GITHUB_BOUND_PROJECT, repository_owner="acme", repository_owner_id="222"
        )

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403

    def test_an_allowed_owner_reaches_its_bound_project(self):
        instance = {**_GITHUB_COM_INSTANCE, "allowed_owner_ids": ["42", "111"]}

        outcome, _, mock_svc = _ingest_via_github(instance, _GITHUB_BOUND_PROJECT)

        assert not isinstance(outcome, HTTPException)
        assert outcome.id == "proj-gh-1"
        mock_svc.sync_team_from_github.assert_awaited_once()

    def test_an_allowed_owner_auto_creates_on_the_shared_issuer(self):
        instance = {**_GITHUB_COM_INSTANCE, "allowed_owner_ids": ["111"], "auto_create_projects": True}

        outcome, projects_coll, _ = _ingest_via_github(instance, None)

        assert not isinstance(outcome, HTTPException)
        assert outcome.github_repository_path == "acme/widgets"
        projects_coll.find_one_and_update.assert_called_once()

    def test_the_shared_issuer_refuses_auto_create_without_a_list(self):
        instance = {**_GITHUB_COM_INSTANCE, "allowed_owner_ids": [], "auto_create_projects": True}

        outcome, projects_coll, mock_svc = _ingest_via_github(instance, None)

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        assert "allow" in outcome.detail.lower()
        projects_coll.find_one_and_update.assert_not_called()
        mock_svc.sync_team_from_github.assert_not_called()

    def test_a_stored_instance_without_the_field_refuses_auto_create_on_the_shared_issuer(self):
        instance = {**_GITHUB_COM_INSTANCE, "auto_create_projects": True}

        outcome, projects_coll, _ = _ingest_via_github(instance, None)

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        projects_coll.find_one_and_update.assert_not_called()

    def test_the_shared_issuer_without_a_list_still_ingests_into_a_bound_project(self):
        instance = {**_GITHUB_COM_INSTANCE, "auto_create_projects": True}

        outcome, _, _ = _ingest_via_github(instance, _GITHUB_BOUND_PROJECT, repository_owner_id="999")

        assert not isinstance(outcome, HTTPException)
        assert outcome.id == "proj-gh-1"

    def test_ghes_auto_creates_without_a_list(self):
        instance = {**_GITHUB_COM_INSTANCE, "url": _GHES_ISSUER, "auto_create_projects": True}

        outcome, projects_coll, _ = _ingest_via_github(instance, None, issuer=_GHES_ISSUER, repository_owner_id=None)

        assert not isinstance(outcome, HTTPException)
        projects_coll.find_one_and_update.assert_called_once()

    def test_an_enterprise_scoped_issuer_is_not_the_shared_one(self):
        enterprise_issuer = f"{_GITHUB_COM_ISSUER}/acme-enterprise"
        instance = {**_GITHUB_COM_INSTANCE, "url": enterprise_issuer, "auto_create_projects": True}

        outcome, projects_coll, _ = _ingest_via_github(instance, None, issuer=enterprise_issuer)

        assert not isinstance(outcome, HTTPException)
        projects_coll.find_one_and_update.assert_called_once()

    def test_a_ghes_list_is_enforced_too(self):
        instance = {**_GITHUB_COM_INSTANCE, "url": _GHES_ISSUER, "allowed_owner_ids": ["111"]}

        outcome, projects_coll, _ = _ingest_via_github(
            instance, _GITHUB_BOUND_PROJECT, issuer=_GHES_ISSUER, repository_owner_id="7"
        )

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        projects_coll.find_one.assert_not_called()


_GITHUB_AUTO_CREATE_INSTANCE = {
    **_GITHUB_COM_INSTANCE,
    "sync_teams": False,
    "auto_create_projects": True,
    "allowed_owner_ids": ["111"],
}


class TestIngestGitHubInitialAdmin:
    """The actor claim is a GitHub login: only the account GitHub vouches for becomes the new project's admin."""

    def test_an_account_named_like_the_actor_is_not_made_admin(self):
        outcome, _, _ = _ingest_via_github(
            _GITHUB_AUTO_CREATE_INSTANCE,
            any_user={"_id": "u-named-like-actor", "username": "developer"},
            actor="developer",
        )

        assert outcome.members == []

    def test_the_account_the_actor_login_resolves_to_is_made_admin(self):
        outcome, _, mock_svc = _ingest_via_github(
            _GITHUB_AUTO_CREATE_INSTANCE, actor_resolution={"_id": "u-ada"}, actor="ada-gh"
        )

        assert [(member.user_id, member.role) for member in outcome.members] == [("u-ada", "admin")]
        assert mock_svc.resolve_login.await_args.args[0] == "ada-gh"


_GITLAB_COM_INSTANCE = {
    "_id": "gl-inst-a",
    "name": "GitLab.com",
    "url": "https://gitlab.com",
    "is_active": True,
    "created_by": "admin",
    "sync_teams": False,
}
_GITLAB_BOUND_PROJECT = {
    "_id": "proj-gl-1",
    "name": "acme/widgets",
    "gitlab_instance_id": "gl-inst-a",
    "gitlab_project_id": 42,
    "gitlab_project_path": "acme/widgets",
}


def _ingest_via_gitlab(instance_doc, project_doc=None, project_path="acme/widgets"):
    """Run a GitLab OIDC ingest; returns the outcome (project or HTTPException) and the projects mock."""
    from app.api.deps import get_project_for_ingest

    projects_coll = create_mock_collection(find_one=project_doc)
    projects_coll.find_one_and_update = AsyncMock(side_effect=lambda _q, update, **_kw: update["$setOnInsert"])
    db = create_mock_db(
        {
            "system_settings": create_mock_collection(find_one=None),
            "gitlab_instances": create_mock_collection(find_one=instance_doc),
            "github_instances": create_mock_collection(find_one=None),
            "projects": projects_coll,
            "users": create_mock_collection(find_one=None),
        }
    )
    with patch("jose.jwt.get_unverified_claims", return_value={"iss": instance_doc["url"]}):
        with patch("app.api.deps.GitLabService") as MockService:
            mock_svc = MagicMock()
            mock_svc.validate_oidc_token = AsyncMock(
                return_value=make_oidc_payload(project_id="42", project_path=project_path)
            )
            MockService.return_value = mock_svc
            try:
                outcome = asyncio.run(get_project_for_ingest(x_api_key=None, oidc_token="a.b.c", db=db))
            except HTTPException as exc:
                outcome = exc
    return outcome, projects_coll


class TestIngestGitLabNamespaceAllowlist:
    """Any gitlab.com project can mint a token for any audience, so its top-level group decides admission."""

    def test_a_foreign_namespace_is_refused_before_the_project_lookup(self):
        instance = {**_GITLAB_COM_INSTANCE, "allowed_namespaces": ["acme"], "auto_create_projects": True}

        outcome, projects_coll = _ingest_via_gitlab(instance, _GITLAB_BOUND_PROJECT, project_path="evil/widgets")

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        projects_coll.find_one.assert_not_called()
        projects_coll.find_one_and_update.assert_not_called()

    def test_a_namespace_sharing_only_a_prefix_is_refused(self):
        instance = {**_GITLAB_COM_INSTANCE, "allowed_namespaces": ["acme"]}

        outcome, projects_coll = _ingest_via_gitlab(instance, _GITLAB_BOUND_PROJECT, project_path="acme-evil/widgets")

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        projects_coll.find_one.assert_not_called()

    def test_an_allowed_namespace_matches_case_insensitively_at_any_depth(self):
        instance = {**_GITLAB_COM_INSTANCE, "allowed_namespaces": ["Acme"]}

        outcome, _ = _ingest_via_gitlab(instance, _GITLAB_BOUND_PROJECT, project_path="acme/platform/widgets")

        assert not isinstance(outcome, HTTPException)
        assert outcome.id == "proj-gl-1"

    def test_an_allowed_namespace_auto_creates_on_gitlab_com(self):
        instance = {**_GITLAB_COM_INSTANCE, "allowed_namespaces": ["acme"], "auto_create_projects": True}

        outcome, projects_coll = _ingest_via_gitlab(instance, None)

        assert not isinstance(outcome, HTTPException)
        assert outcome.gitlab_project_path == "acme/widgets"
        projects_coll.find_one_and_update.assert_called_once()

    def test_gitlab_com_refuses_auto_create_without_a_list(self):
        instance = {**_GITLAB_COM_INSTANCE, "auto_create_projects": True}

        outcome, projects_coll = _ingest_via_gitlab(instance, None)

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        assert "allow" in outcome.detail.lower()
        projects_coll.find_one_and_update.assert_not_called()

    def test_gitlab_com_without_a_list_still_ingests_into_a_bound_project(self):
        instance = {**_GITLAB_COM_INSTANCE, "auto_create_projects": True}

        outcome, _ = _ingest_via_gitlab(instance, _GITLAB_BOUND_PROJECT, project_path="anyone/widgets")

        assert not isinstance(outcome, HTTPException)
        assert outcome.id == "proj-gl-1"

    def test_a_self_managed_instance_auto_creates_without_a_list(self):
        instance = {**_GITLAB_COM_INSTANCE, "url": "https://gitlab.example.com", "auto_create_projects": True}

        outcome, projects_coll = _ingest_via_gitlab(instance, None, project_path="anyone/widgets")

        assert not isinstance(outcome, HTTPException)
        projects_coll.find_one_and_update.assert_called_once()


_WRITE_GITLAB_INSTANCE = {
    "_id": "gl-inst-w",
    "name": "GitLab W",
    "url": "https://gitlab-w.example.com",
    "access_token": "glpat-secret",
    "is_active": True,
    "created_by": "admin",
    "auto_create_projects": True,
    "sync_teams": True,
}


def _authorize_write_via_gitlab(project_doc, target_project_id):
    """Run authorize_project_write with a GitLab CI token; returns the outcome, projects and service mocks."""
    from app.api.deps import authorize_project_write
    from app.models.team import TeamSyncResult

    projects_coll = create_mock_collection(find_one=project_doc)
    db = create_mock_db(
        {
            "gitlab_instances": create_mock_collection(find_one=_WRITE_GITLAB_INSTANCE),
            "github_instances": create_mock_collection(find_one=None),
            "projects": projects_coll,
            "users": create_mock_collection(find_one=None),
            "system_settings": create_mock_collection(find_one=None),
        }
    )
    with (
        patch("jose.jwt.get_unverified_claims", return_value={"iss": _WRITE_GITLAB_INSTANCE["url"]}),
        patch("app.api.deps.GitLabService") as MockService,
    ):
        mock_svc = MockService.return_value
        mock_svc.validate_oidc_token = AsyncMock(
            return_value=make_oidc_payload(project_id="99", project_path="group/renamed", user_email="dev@test.com")
        )
        mock_svc.sync_team_from_gitlab = AsyncMock(return_value=TeamSyncResult(["t-1"]))
        try:
            outcome = asyncio.run(
                authorize_project_write(target_project_id, x_api_key=None, oidc_token="a.b.c", token=None, db=db)
            )
        except HTTPException as exc:
            outcome = exc
    return outcome, projects_coll, mock_svc


class TestCiWriteAuthorizationProvisionsNothing:
    """A CI write is authorized against a project that exists; it neither creates, renames nor syncs one."""

    def test_an_unknown_repository_is_refused_without_creating_a_project(self):
        outcome, projects_coll, mock_svc = _authorize_write_via_gitlab(None, "proj-any")

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403
        projects_coll.find_one_and_update.assert_not_called()
        mock_svc.sync_team_from_gitlab.assert_not_called()

    def test_a_bound_project_is_authorized_without_a_write(self):
        project_doc = {
            "_id": "proj-w",
            "name": "group/old-name",
            "gitlab_instance_id": "gl-inst-w",
            "gitlab_project_id": 99,
            "gitlab_project_path": "group/old-name",
        }

        outcome, projects_coll, mock_svc = _authorize_write_via_gitlab(project_doc, "proj-w")

        assert outcome == "proj-w"
        projects_coll.update_one.assert_not_called()
        mock_svc.sync_team_from_gitlab.assert_not_called()

    def test_credentials_of_another_project_are_refused(self):
        project_doc = {
            "_id": "proj-w",
            "name": "group/renamed",
            "gitlab_instance_id": "gl-inst-w",
            "gitlab_project_id": 99,
        }

        outcome, _, _ = _authorize_write_via_gitlab(project_doc, "proj-other")

        assert isinstance(outcome, HTTPException)
        assert outcome.status_code == 403

    def test_an_unknown_github_repository_is_refused_without_creating_a_project(self):
        from app.api.deps import authorize_project_write

        projects_coll = create_mock_collection(find_one=None)
        db = create_mock_db(
            {
                "gitlab_instances": create_mock_collection(find_one=None),
                "github_instances": create_mock_collection(
                    find_one={**_GITHUB_COM_INSTANCE, "auto_create_projects": True, "allowed_owner_ids": ["111"]}
                ),
                "projects": projects_coll,
                "users": create_mock_collection(find_one=None),
                "system_settings": create_mock_collection(find_one=None),
            }
        )
        with (
            patch("jose.jwt.get_unverified_claims", return_value={"iss": _GITHUB_COM_ISSUER}),
            patch("app.api.deps.GitHubService") as MockService,
        ):
            mock_svc = MockService.return_value
            mock_svc.validate_oidc_token = AsyncMock(
                return_value=make_github_oidc_payload(repository_owner_id="111", repository_owner="acme")
            )
            mock_svc.sync_team_from_github = AsyncMock()
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(authorize_project_write("proj-any", x_api_key=None, oidc_token="a.b.c", token=None, db=db))

        assert exc_info.value.status_code == 403
        projects_coll.find_one_and_update.assert_not_called()
        mock_svc.sync_team_from_github.assert_not_called()


class TestMalformedOidcTokenLogging:
    def test_an_undecodable_token_is_one_warning_without_a_traceback(self, caplog):
        from app.api.deps import get_project_for_ingest

        with caplog.at_level("WARNING", logger="app.api.deps"), pytest.raises(HTTPException) as exc_info:
            asyncio.run(get_project_for_ingest(x_api_key=None, oidc_token="not.a.jwt", db=MagicMock()))

        assert exc_info.value.status_code == 403
        assert [(r.levelname, r.exc_info) for r in caplog.records] == [("WARNING", None)]
