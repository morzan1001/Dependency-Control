"""Tests for GitLab instance API endpoints.

Tests model behavior and endpoint functions for CRUD operations,
connection testing, and uniqueness validation.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.gitlab_instance import GitLabInstance
from tests.mocks.gitlab import make_gitlab_instance


# ---------------------------------------------------------------------------
# Model tests (existing)
# ---------------------------------------------------------------------------


class TestGitLabInstanceModelDefaults:
    def test_default_values(self):
        instance = GitLabInstance(
            name="Test",
            url="https://gitlab.com",
            created_by="admin",
        )
        assert instance.is_active is True
        assert instance.is_default is False
        assert instance.auto_create_projects is False
        assert instance.sync_teams is False
        assert instance.access_token is None
        assert instance.oidc_audience is None

    def test_id_auto_generated(self):
        instance = GitLabInstance(
            name="Test",
            url="https://gitlab.com",
            created_by="admin",
        )
        assert instance.id is not None
        assert len(instance.id) > 0

    def test_two_instances_have_different_ids(self):
        a = GitLabInstance(name="A", url="https://a.com", created_by="admin")
        b = GitLabInstance(name="B", url="https://b.com", created_by="admin")
        assert a.id != b.id


class TestGitLabInstanceSerialization:
    def test_access_token_excluded_from_model_dump(self):
        instance = make_gitlab_instance(access_token="secret-token")
        dumped = instance.model_dump()
        assert "access_token" not in dumped

    def test_id_uses_alias_in_dump(self):
        instance = make_gitlab_instance(id="custom-id")
        dumped = instance.model_dump(by_alias=True)
        assert dumped["_id"] == "custom-id"

    def test_populate_by_alias(self):
        data = {
            "_id": "from-alias",
            "name": "Test",
            "url": "https://gitlab.com",
            "created_by": "admin",
        }
        instance = GitLabInstance(**data)
        assert instance.id == "from-alias"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MODULE = "app.api.v1.endpoints.gitlab_instances"


def _make_repo_mock(**method_returns):
    """Create a mock GitLabInstanceRepository with configured async return values."""
    mock_repo = MagicMock()
    for method_name, return_value in method_returns.items():
        setattr(mock_repo, method_name, AsyncMock(return_value=return_value))
    return mock_repo


def _patch_response():
    """Context manager that injects a mock Response into the module (missing import)."""
    import contextlib

    import app.api.v1.endpoints.gitlab_instances as mod

    @contextlib.contextmanager
    def _ctx():
        mock_response_cls = MagicMock()
        original = getattr(mod, "Response", None)
        mod.Response = mock_response_cls
        try:
            yield mock_response_cls
        finally:
            if original is None:
                delattr(mod, "Response")
            else:
                mod.Response = original

    return _ctx()


def _make_gitlab_service_mock(response):
    """Create a patched GitLabService whose _api_client returns the given response."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    mock_svc = MagicMock()
    mock_svc._api_client.return_value = mock_client
    mock_svc.api_url = "https://gitlab.test.com/api/v4"
    mock_svc._get_auth_headers.return_value = {"PRIVATE-TOKEN": "tok"}
    return mock_svc


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------


class TestListInstances:
    def test_list_all_instances(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        instances = [
            make_gitlab_instance(id="i1", name="A"),
            make_gitlab_instance(id="i2", name="B"),
        ]
        mock_repo = _make_repo_mock(list_all=instances, count_all=2)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=1,
                    size=100,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["total"] == 2
        assert len(result["items"]) == 2
        mock_repo.list_all.assert_called_once_with(skip=0, limit=100)

    def test_list_active_only(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        active = [make_gitlab_instance(id="i1", name="Active")]
        mock_repo = _make_repo_mock(list_active=active, count_active=1)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=1,
                    size=100,
                    active_only=True,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["total"] == 1
        mock_repo.list_active.assert_called_once()
        mock_repo.list_all.assert_not_called()

    def test_pagination_offset(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        mock_repo = _make_repo_mock(list_all=[], count_all=50)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=3,
                    size=10,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        mock_repo.list_all.assert_called_once_with(skip=20, limit=10)
        assert result["total"] == 50

    def test_empty_list(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import list_instances

        mock_repo = _make_repo_mock(list_all=[], count_all=0)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=1,
                    size=100,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["total"] == 0
        assert result["items"] == []


class TestGetInstance:
    def test_returns_instance(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import get_instance

        instance = make_gitlab_instance(id="inst-1", name="My GL")
        mock_repo = _make_repo_mock(get_by_id=instance)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                get_instance(
                    instance_id="inst-1",
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result.id == "inst-1"
        assert result.name == "My GL"

    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import get_instance

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    get_instance(
                        instance_id="missing",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 404


class TestCreateInstance:
    def _make_create_data(self, **overrides):
        from app.schemas.gitlab_instance import GitLabInstanceCreate

        defaults = {
            "name": "New GL",
            "url": "https://new-gitlab.com",
            "access_token": "glpat-new-token",
        }
        defaults.update(overrides)
        return GitLabInstanceCreate(**defaults)

    def test_raises_400_on_duplicate_url(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=True)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "URL" in exc_info.value.detail

    def test_raises_400_on_duplicate_name(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=True)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "name" in exc_info.value.detail

    def test_raises_400_on_connection_failure(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_response = MagicMock(status_code=401)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        create_instance(
                            instance_data=self._make_create_data(),
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )
        assert exc_info.value.status_code == 400
        assert "Failed to connect" in exc_info.value.detail

    def test_success_creates_and_returns_instance(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import create_instance

        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)
        mock_repo.create = AsyncMock(side_effect=lambda inst: inst)
        mock_response = MagicMock(status_code=200)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    create_instance(
                        instance_data=self._make_create_data(),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.name == "New GL"
        mock_repo.create.assert_called_once()


class TestUpdateInstance:
    def _make_update_data(self, **fields):
        from app.schemas.gitlab_instance import GitLabInstanceUpdate

        return GitLabInstanceUpdate(**fields)

    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    update_instance(
                        instance_id="missing",
                        update_data=self._make_update_data(name="New Name"),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 404

    def test_raises_400_on_duplicate_url(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", url="https://old.com")
        mock_repo = _make_repo_mock(get_by_id=existing, exists_by_url=True)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    update_instance(
                        instance_id="inst-1",
                        update_data=self._make_update_data(url="https://taken.com"),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "URL" in exc_info.value.detail

    def test_raises_400_on_duplicate_name(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", name="Old Name")
        mock_repo = _make_repo_mock(
            get_by_id=existing,
            exists_by_name=True,
        )

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    update_instance(
                        instance_id="inst-1",
                        update_data=self._make_update_data(name="Taken Name"),
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 400
        assert "name" in exc_info.value.detail

    def test_success_returns_updated_instance(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", name="Old")
        updated = make_gitlab_instance(id="inst-1", name="New Name")
        mock_repo = _make_repo_mock(update=True, exists_by_name=False)
        # get_by_id called twice: first for existence check, then for refresh
        mock_repo.get_by_id = AsyncMock(side_effect=[existing, updated])

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                update_instance(
                    instance_id="inst-1",
                    update_data=self._make_update_data(name="New Name"),
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result.name == "New Name"
        mock_repo.update.assert_called_once()

    def test_set_as_default_calls_repo(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import update_instance

        existing = make_gitlab_instance(id="inst-1", is_default=False)
        updated = make_gitlab_instance(id="inst-1", is_default=True)
        mock_repo = _make_repo_mock(update=True, set_as_default=True)
        mock_repo.get_by_id = AsyncMock(side_effect=[existing, updated])

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                update_instance(
                    instance_id="inst-1",
                    update_data=self._make_update_data(is_default=True),
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result.is_default is True
        mock_repo.set_as_default.assert_called_once_with("inst-1")


class TestDeleteInstance:
    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import delete_instance

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.ProjectRepository"):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        delete_instance(
                            instance_id="missing",
                            force=False,
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )
        assert exc_info.value.status_code == 404

    def test_raises_400_when_projects_linked(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import delete_instance

        existing = make_gitlab_instance(id="inst-1", name="GL")
        mock_repo = _make_repo_mock(get_by_id=existing)

        mock_proj_repo = MagicMock()
        mock_proj_repo.count_by_instance = AsyncMock(return_value=3)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.ProjectRepository", return_value=mock_proj_repo):
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(
                        delete_instance(
                            instance_id="inst-1",
                            force=False,
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )
        assert exc_info.value.status_code == 400
        assert "3 projects" in exc_info.value.detail

    def test_force_deletes_despite_linked_projects(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import delete_instance

        existing = make_gitlab_instance(id="inst-1", name="GL")
        mock_repo = _make_repo_mock(get_by_id=existing, delete=True)

        mock_proj_repo = MagicMock()
        mock_proj_repo.count_by_instance = AsyncMock(return_value=3)

        with _patch_response():
            with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
                with patch(f"{MODULE}.ProjectRepository", return_value=mock_proj_repo):
                    asyncio.run(
                        delete_instance(
                            instance_id="inst-1",
                            force=True,
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )
        mock_repo.delete.assert_called_once_with("inst-1")

    def test_success_deletes_instance(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import delete_instance

        existing = make_gitlab_instance(id="inst-1", name="GL")
        mock_repo = _make_repo_mock(get_by_id=existing, delete=True)

        mock_proj_repo = MagicMock()
        mock_proj_repo.count_by_instance = AsyncMock(return_value=0)

        with _patch_response():
            with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
                with patch(f"{MODULE}.ProjectRepository", return_value=mock_proj_repo):
                    asyncio.run(
                        delete_instance(
                            instance_id="inst-1",
                            force=False,
                            db=MagicMock(),
                            current_user=admin_user,
                        )
                    )
        mock_repo.delete.assert_called_once_with("inst-1")


class TestTestConnection:
    def test_raises_404_when_not_found(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    test_connection(
                        instance_id="missing",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )
        assert exc_info.value.status_code == 404

    def test_no_token_returns_failure(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token=None)
        mock_repo = _make_repo_mock(get_by_id=instance)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                test_connection(
                    instance_id="inst-1",
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result.success is False
        assert "No access token" in result.message

    def test_success_returns_version(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token="glpat-tok")
        mock_repo = _make_repo_mock(get_by_id=instance)

        mock_response = MagicMock(status_code=200)
        mock_response.json.return_value = {"version": "16.5.0"}

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    test_connection(
                        instance_id="inst-1",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.success is True
        assert result.gitlab_version == "16.5.0"

    def test_http_error_returns_failure(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token="glpat-tok")
        mock_repo = _make_repo_mock(get_by_id=instance)

        mock_response = MagicMock(status_code=403)

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=_make_gitlab_service_mock(mock_response)):
                result = asyncio.run(
                    test_connection(
                        instance_id="inst-1",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.success is False
        assert "403" in result.message

    def test_exception_returns_failure(self, admin_user):
        from app.api.v1.endpoints.gitlab_instances import test_connection

        instance = make_gitlab_instance(id="inst-1", access_token="glpat-tok")
        mock_repo = _make_repo_mock(get_by_id=instance)

        mock_response = MagicMock()
        mock_svc = _make_gitlab_service_mock(mock_response)
        # Override client.get to raise instead of returning a response
        mock_svc._api_client.return_value.__aenter__.return_value.get = AsyncMock(
            side_effect=ConnectionError("DNS resolution failed")
        )

        with patch(f"{MODULE}.GitLabInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitLabService", return_value=mock_svc):
                result = asyncio.run(
                    test_connection(
                        instance_id="inst-1",
                        db=MagicMock(),
                        current_user=admin_user,
                    )
                )

        assert result.success is False
        assert "DNS resolution failed" in result.message
