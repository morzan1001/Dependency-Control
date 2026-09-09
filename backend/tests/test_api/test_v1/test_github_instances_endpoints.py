"""Tests for GitHub instance API endpoints."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.services.github import GitHubService
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


def _run_test_connection(instance, current_user, jwks, orgs=None):
    """Drive test_connection with the two outbound calls stubbed; returns (response, org_probe_mock)."""
    from app.api.v1.endpoints.github_instances import test_connection

    mock_repo = _make_repo_mock(get_by_id=instance)
    org_probe = AsyncMock(return_value=orgs)

    with (
        patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo),
        patch.object(GitHubService, "get_jwks", new=AsyncMock(return_value=jwks)),
        patch.object(GitHubService, "get_viewer_organisations", new=org_probe),
    ):
        result = asyncio.run(test_connection(instance_id="gh-1", db=MagicMock(), current_user=current_user))

    return result, org_probe


class TestConnectionChecksTheToken:
    """A green connection test must mean team sync will work, not merely that OIDC is reachable."""

    def test_reports_the_org_read_failure_instead_of_a_bare_success(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        # None is the service's "the API refused" signal.
        result, _ = _run_test_connection(instance, admin_user, jwks={"keys": [{}]}, orgs=None)

        assert result.success is False
        assert "read:org" in result.message

    def test_treats_membership_in_no_organisation_as_a_failure_too(self, admin_user):
        """A token that lists zero organisations syncs zero teams, however willing the API was to answer."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, _ = _run_test_connection(instance, admin_user, jwks={"keys": [{}]}, orgs=[])

        assert result.success is False
        assert "read:org" in result.message

    def test_stays_silent_about_the_org_when_team_sync_is_off(self, admin_user):
        """An instance that only ingests needs no org access; demanding it would fail a fine setup."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=False)

        result, org_probe = _run_test_connection(instance, admin_user, jwks={"keys": [{}]})

        assert result.success is True
        org_probe.assert_not_called()

    def test_success_names_the_signing_keys_and_the_organisation_count(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, _ = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}, {}]},
            orgs=[{"login": "acme"}, {"login": "globex"}],
        )

        assert result.success is True
        assert "2 signing key(s)" in result.message
        assert "2 organisation(s)" in result.message

    def test_a_jwks_failure_stays_a_jwks_failure_and_never_probes_the_org(self, admin_user):
        """An operator must be able to tell an unreachable issuer from a token that cannot read the org."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, org_probe = _run_test_connection(instance, admin_user, jwks={"keys": []})

        assert result.success is False
        assert "read:org" not in result.message
        org_probe.assert_not_called()
