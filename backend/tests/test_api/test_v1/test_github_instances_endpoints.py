"""Tests for GitHub instance API endpoints."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from tests.mocks.github import make_github_instance

MODULE = "app.api.v1.endpoints.github_instances"


def _make_repo_mock(**method_returns):
    mock_repo = MagicMock()
    for method_name, return_value in method_returns.items():
        setattr(mock_repo, method_name, AsyncMock(return_value=return_value))
    return mock_repo


def _run_update(instance, current_user, **fields):
    """Drive update_instance against a repository that answers with ``instance``."""
    from app.api.v1.endpoints.github_instances import update_instance
    from app.schemas.github_instance import GitHubInstanceUpdate

    mock_repo = _make_repo_mock(get_by_id=instance, exists_by_url=False, exists_by_name=False, update=True)

    with patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo):
        asyncio.run(
            update_instance(
                instance_id="gh-1",
                update_data=GitHubInstanceUpdate(**fields),
                db=MagicMock(),
                current_user=current_user,
            )
        )
    return mock_repo


class TestGitHubInstancePagination:
    def test_pagination_response_page_reflects_requested_page(self, admin_user):
        """build_pagination_response must receive skip, not the 1-based page (else page=2/size=100 collapses to 1)."""
        from app.api.v1.endpoints.github_instances import list_instances

        mock_repo = _make_repo_mock(list_all=[], count_all=250)

        with patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=2,
                    size=100,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["page"] == 2
        assert result["size"] == 100
        assert result["pages"] == 3


class TestGitHubInstanceSyncTeams:
    def test_create_persists_and_returns_sync_teams(self, admin_user):
        from app.api.v1.endpoints.github_instances import create_instance
        from app.schemas.github_instance import GitHubInstanceCreate

        created = []
        mock_repo = _make_repo_mock(exists_by_url=False, exists_by_name=False)

        async def _create(instance):
            created.append(instance)
            return instance

        mock_repo.create = AsyncMock(side_effect=_create)
        service = MagicMock()
        service.get_jwks = AsyncMock(return_value={"keys": [{"kid": "k1"}]})

        payload = GitHubInstanceCreate(
            name="GitHub.com",
            url="https://token.actions.githubusercontent.com",
            oidc_audience="dependency-control",
            access_token="ghp-secret",
            sync_teams=True,
        )

        with patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo):
            with patch(f"{MODULE}.GitHubService", return_value=service):
                response = asyncio.run(create_instance(instance_data=payload, db=MagicMock(), current_user=admin_user))

        assert created[0].sync_teams is True
        assert response.sync_teams is True


class TestGitHubInstanceUpdateTokenGuard:
    """The create-time validator is decorative if an update can flip sync_teams on without a token."""

    def test_enabling_sync_teams_without_any_token_is_rejected(self, admin_user):
        instance = make_github_instance(id="gh-1", access_token=None)

        with pytest.raises(HTTPException) as exc_info:
            _run_update(instance, admin_user, sync_teams=True)

        assert exc_info.value.status_code == 400
        assert "access token" in exc_info.value.detail

    def test_enabling_sync_teams_together_with_a_token_is_allowed(self, admin_user):
        instance = make_github_instance(id="gh-1", access_token=None)

        repo = _run_update(instance, admin_user, sync_teams=True, access_token="ghp-secret")

        assert repo.update.await_args.args[1]["sync_teams"] is True

    def test_enabling_sync_teams_on_an_instance_that_already_has_a_token_is_allowed(self, admin_user):
        instance = make_github_instance(id="gh-1", access_token="ghp-stored")

        repo = _run_update(instance, admin_user, sync_teams=True)

        assert repo.update.await_args.args[1]["sync_teams"] is True

    def test_clearing_the_token_while_sync_teams_stays_on_is_rejected(self, admin_user):
        instance = make_github_instance(id="gh-1", access_token="ghp-stored", sync_teams=True)

        with pytest.raises(HTTPException) as exc_info:
            _run_update(instance, admin_user, access_token=None)

        assert exc_info.value.status_code == 400
