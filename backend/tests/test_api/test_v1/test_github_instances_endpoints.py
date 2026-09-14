"""Tests for GitHub instance API endpoints."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.services.github import GitHubCoreRateLimit, GitHubService
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


def _spent_budget(minutes_until_reset=20):
    return GitHubCoreRateLimit(
        remaining=0, reset_at=datetime.now(timezone.utc) + timedelta(minutes=minutes_until_reset)
    )


_HEALTHY_BUDGET = GitHubCoreRateLimit(remaining=4999, reset_at=datetime.now(timezone.utc) + timedelta(minutes=42))


def _run_test_connection(instance, current_user, jwks, orgs=None, team_counts=None, rate_limit=_HEALTHY_BUDGET):
    """Drive test_connection with the outbound calls stubbed; returns (response, org, team, rate-limit probes).

    An intact budget is the default because it is the state a test about anything else assumes: a
    probe refused under it is refused on its own merits.
    """
    from app.api.v1.endpoints.github_instances import test_connection

    mock_repo = _make_repo_mock(get_by_id=instance)
    org_probe = AsyncMock(return_value=orgs)
    counts = team_counts or {}
    team_probe = AsyncMock(side_effect=lambda org: counts[org])
    rate_limit_probe = AsyncMock(return_value=rate_limit)

    with (
        patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo),
        patch.object(GitHubService, "get_jwks", new=AsyncMock(return_value=jwks)),
        patch.object(GitHubService, "get_viewer_organisations", new=org_probe),
        patch.object(GitHubService, "count_org_teams", new=team_probe),
        patch.object(GitHubService, "get_core_rate_limit", new=rate_limit_probe),
    ):
        result = asyncio.run(test_connection(instance_id="gh-1", db=MagicMock(), current_user=current_user))

    return result, org_probe, team_probe, rate_limit_probe


class TestConnectionChecksTheToken:
    """A green connection test must mean team sync will work, not merely that OIDC is reachable."""

    def test_reports_the_org_read_failure_instead_of_a_bare_success(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        # None is the service's "the API refused" signal.
        result, *_ = _run_test_connection(instance, admin_user, jwks={"keys": [{}]}, orgs=None)

        assert result.success is False
        assert "read:org" in result.message

    def test_treats_membership_in_no_organisation_as_a_failure_too(self, admin_user):
        """A token that lists zero organisations syncs zero teams, however willing the API was to answer."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(instance, admin_user, jwks={"keys": [{}]}, orgs=[])

        assert result.success is False
        assert "read:org" in result.message

    def test_stays_silent_about_the_org_when_team_sync_is_off(self, admin_user):
        """An instance that only ingests needs no org access; demanding it would fail a fine setup."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=False)

        result, org_probe, team_probe, _ = _run_test_connection(instance, admin_user, jwks={"keys": [{}]})

        assert result.success is True
        org_probe.assert_not_called()
        team_probe.assert_not_called()

    def test_a_jwks_failure_stays_a_jwks_failure_and_never_probes_the_org(self, admin_user):
        """An operator must be able to tell an unreachable issuer from a token that cannot read the org."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, org_probe, team_probe, _ = _run_test_connection(instance, admin_user, jwks={"keys": []})

        assert result.success is False
        assert "read:org" not in result.message
        org_probe.assert_not_called()
        team_probe.assert_not_called()


class TestConnectionProbesEveryOrganisation:
    """The owner runs several organisations; a token green on one and blind on another is the §8 failure."""

    def test_success_names_every_organisation_with_its_team_count(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, _, team_probe, _ = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}, {}]},
            orgs=[{"login": "acme"}, {"login": "globex"}],
            team_counts={"acme": 7, "globex": 3},
        )

        assert result.success is True
        assert "2 signing key(s)" in result.message
        # Each count must come from its own organisation's probe, not be reused across them.
        assert "acme (7 team(s))" in result.message
        assert "globex (3 team(s))" in result.message
        assert [call.args[0] for call in team_probe.await_args_list] == ["acme", "globex"]

    def test_one_unreadable_organisation_among_several_fails_and_names_it(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}]},
            orgs=[{"login": "acme"}, {"login": "globex"}],
            team_counts={"acme": 7, "globex": None},
        )

        assert result.success is False
        assert "globex" in result.message
        # Naming the healthy organisation too would leave the operator guessing which one to fix.
        assert "acme" not in result.message

    def test_an_organisation_with_no_teams_is_a_success(self, admin_user):
        """Zero teams is an answer; only a refusal is a failure."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}]},
            orgs=[{"login": "acme"}],
            team_counts={"acme": 0},
        )

        assert result.success is True
        assert "acme (0 team(s))" in result.message


class TestBindingPickerListings:
    """What the team-binding dialog offers; a picker that cannot list makes binding guesswork."""

    @staticmethod
    def _run(endpoint, instance, **service_returns):
        """Drive a picker route; returns (result, the stubbed service) so its probes can be asserted on."""
        mock_repo = _make_repo_mock(get_by_id=instance)
        service = MagicMock()
        # An intact budget unless the test is about the budget: a refusal under it is a scope refusal.
        for name, value in {"get_core_rate_limit": _HEALTHY_BUDGET, **service_returns}.items():
            setattr(service, name, AsyncMock(return_value=value))

        with (
            patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo),
            patch(f"{MODULE}.GitHubService", return_value=service),
        ):
            return asyncio.run(endpoint), service

    def test_the_organisations_of_the_token_are_offered(self, admin_user):
        from app.api.v1.endpoints.github_instances import list_instance_organisations

        result, service = self._run(
            list_instance_organisations(instance_id="gh-1", db=MagicMock(), current_user=admin_user),
            make_github_instance(access_token="ghp-test-token"),
            get_viewer_organisations=[{"login": "acme"}, {"login": "globex"}, {}],
        )

        assert result == ["acme", "globex"]
        service.get_core_rate_limit.assert_not_called()

    def test_a_token_that_cannot_list_organisations_is_a_bad_gateway(self, admin_user):
        from app.api.v1.endpoints.github_instances import list_instance_organisations

        with pytest.raises(HTTPException) as excinfo:
            self._run(
                list_instance_organisations(instance_id="gh-1", db=MagicMock(), current_user=admin_user),
                make_github_instance(access_token="ghp-test-token"),
                get_viewer_organisations=None,
            )

        assert excinfo.value.status_code == 502
        assert "read:org" in excinfo.value.detail
        assert "rate limit" not in excinfo.value.detail

    def test_each_team_is_offered_with_the_parent_that_tells_it_apart(self, admin_user):
        from app.api.v1.endpoints.github_instances import list_organisation_teams

        result, service = self._run(
            list_organisation_teams(instance_id="gh-1", org="acme", db=MagicMock(), current_user=admin_user),
            make_github_instance(access_token="ghp-test-token"),
            get_org_teams=[
                {"id": 4711, "slug": "payments", "name": "Payments", "parent": None},
                {
                    "id": 900,
                    "slug": "cards",
                    "name": "Cards",
                    "parent": {"id": 4711, "slug": "payments", "name": "Payments"},
                },
            ],
        )

        assert [(team.id, team.slug, team.name, team.parent_name) for team in result] == [
            (4711, "payments", "Payments", None),
            (900, "cards", "Cards", "Payments"),
        ]
        service.get_core_rate_limit.assert_not_called()

    def test_an_unreadable_organisation_is_a_bad_gateway(self, admin_user):
        from app.api.v1.endpoints.github_instances import list_organisation_teams

        with pytest.raises(HTTPException) as excinfo:
            self._run(
                list_organisation_teams(instance_id="gh-1", org="acme", db=MagicMock(), current_user=admin_user),
                make_github_instance(access_token="ghp-test-token"),
                get_org_teams=None,
            )

        assert excinfo.value.status_code == 502
        assert "read:org there" in excinfo.value.detail

    def test_an_unknown_instance_is_not_found(self, admin_user):
        from app.api.v1.endpoints.github_instances import list_organisation_teams

        mock_repo = _make_repo_mock(get_by_id=None)

        with patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo):
            with pytest.raises(HTTPException) as excinfo:
                asyncio.run(
                    list_organisation_teams(
                        instance_id="gh-absent", org="acme", db=MagicMock(), current_user=admin_user
                    )
                )

        assert excinfo.value.status_code == 404


class TestPickerListingsTellAThrottledTokenFromAScopeProblem:
    """The picker inherited the connection test's guess: it named read:org for every refusal."""

    def test_a_throttled_organisation_listing_reports_the_wait(self, admin_user):
        from app.api.v1.endpoints.github_instances import list_instance_organisations

        budget = _spent_budget()
        with pytest.raises(HTTPException) as excinfo:
            TestBindingPickerListings._run(
                list_instance_organisations(instance_id="gh-1", db=MagicMock(), current_user=admin_user),
                make_github_instance(access_token="ghp-test-token"),
                get_viewer_organisations=None,
                get_core_rate_limit=budget,
            )

        assert excinfo.value.status_code == 502
        assert "rate limit is exhausted" in excinfo.value.detail
        assert "read:org" not in excinfo.value.detail
        assert f"{budget.reset_at:%Y-%m-%d %H:%M UTC}" in excinfo.value.detail

    def test_a_throttled_team_listing_reports_the_wait(self, admin_user):
        from app.api.v1.endpoints.github_instances import list_organisation_teams

        budget = _spent_budget(minutes_until_reset=5)
        with pytest.raises(HTTPException) as excinfo:
            TestBindingPickerListings._run(
                list_organisation_teams(instance_id="gh-1", org="acme", db=MagicMock(), current_user=admin_user),
                make_github_instance(access_token="ghp-test-token"),
                get_org_teams=None,
                get_core_rate_limit=budget,
            )

        assert excinfo.value.status_code == 502
        assert "rate limit is exhausted" in excinfo.value.detail
        assert "read:org" not in excinfo.value.detail
        assert "5 minute(s)" in excinfo.value.detail

    def test_an_unreadable_budget_admits_it_cannot_tell(self, admin_user):
        """GHES with rate limiting off answers nothing here; neither cause is established, so neither is stated."""
        from app.api.v1.endpoints.github_instances import list_instance_organisations

        with pytest.raises(HTTPException) as excinfo:
            TestBindingPickerListings._run(
                list_instance_organisations(instance_id="gh-1", db=MagicMock(), current_user=admin_user),
                make_github_instance(access_token="ghp-test-token"),
                get_viewer_organisations=None,
                get_core_rate_limit=None,
            )

        assert excinfo.value.status_code == 502
        assert "could not be determined" in excinfo.value.detail
        assert "The token needs read:org." not in excinfo.value.detail


class TestConnectionTellsAThrottledTokenFromAScopeProblem:
    """A token with read:org whose budget is spent 403s exactly like one without the scope."""

    def test_a_throttled_org_probe_reports_the_wait_rather_than_the_scope(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)
        budget = _spent_budget()

        result, _, _, rate_probe = _run_test_connection(
            instance, admin_user, jwks={"keys": [{}]}, orgs=None, rate_limit=budget
        )

        assert result.success is False
        assert "rate limit" in result.message
        assert "read:org" not in result.message
        assert f"{budget.reset_at:%Y-%m-%d %H:%M UTC}" in result.message
        assert "20 minute(s)" in result.message
        rate_probe.assert_awaited_once()

    def test_a_refused_org_probe_still_reports_the_scope(self, admin_user):
        """The budget stands, so the 403 was about permissions after all."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(
            instance, admin_user, jwks={"keys": [{}]}, orgs=None, rate_limit=_HEALTHY_BUDGET
        )

        assert result.success is False
        assert "read:org" in result.message
        assert "rate limit" not in result.message

    def test_an_unreadable_budget_admits_it_cannot_tell(self, admin_user):
        """GHES without rate limiting answers nothing here; naming either cause would be a guess."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(instance, admin_user, jwks={"keys": [{}]}, orgs=None, rate_limit=None)

        assert result.success is False
        assert "could not be determined" in result.message
        assert "Team sync needs read:org" not in result.message
        assert "rate limit is exhausted" not in result.message

    def test_an_unreadable_budget_does_not_accuse_the_organisation_of_the_team_probe(self, admin_user):
        """Exhaustion is still on the table, so the organisations after it stay unnamed."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}]},
            orgs=[{"login": "acme"}, {"login": "globex"}],
            team_counts={"acme": 7, "globex": None},
            rate_limit=None,
        )

        assert result.success is False
        assert "could not be determined" in result.message
        assert "globex" not in result.message

    def test_membership_in_no_organisation_is_never_a_rate_limit(self, admin_user):
        """A 200 carrying an empty list spent budget to say so; asking again would only confuse the message."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, _, _, rate_probe = _run_test_connection(
            instance, admin_user, jwks={"keys": [{}]}, orgs=[], rate_limit=_spent_budget()
        )

        assert result.success is False
        assert "read:org" in result.message
        rate_probe.assert_not_called()

    def test_a_throttled_team_probe_reports_the_wait_rather_than_accusing_the_organisation(self, admin_user):
        """Mid-loop exhaustion makes every remaining organisation look unreadable; none of them is."""
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)
        budget = _spent_budget(minutes_until_reset=7)

        result, _, _, rate_probe = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}]},
            orgs=[{"login": "acme"}, {"login": "globex"}],
            team_counts={"acme": 7, "globex": None},
            rate_limit=budget,
        )

        assert result.success is False
        assert "rate limit" in result.message
        assert "read:org" not in result.message
        assert "globex" not in result.message
        assert f"{budget.reset_at:%Y-%m-%d %H:%M UTC}" in result.message
        assert "7 minute(s)" in result.message
        rate_probe.assert_awaited_once()

    def test_a_refused_team_probe_still_names_the_organisation(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}]},
            orgs=[{"login": "acme"}, {"login": "globex"}],
            team_counts={"acme": 7, "globex": None},
            rate_limit=_HEALTHY_BUDGET,
        )

        assert result.success is False
        assert "globex" in result.message
        assert "read:org" in result.message
        assert "rate limit" not in result.message

    def test_a_green_test_spends_nothing_on_the_budget_endpoint(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, _, _, rate_probe = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}]},
            orgs=[{"login": "acme"}],
            team_counts={"acme": 3},
            rate_limit=_spent_budget(),
        )

        assert result.success is True
        rate_probe.assert_not_called()

    def test_a_reset_already_due_is_not_reported_as_a_negative_wait(self, admin_user):
        instance = make_github_instance(access_token="ghp-test-token", sync_teams=True)

        result, *_ = _run_test_connection(
            instance,
            admin_user,
            jwks={"keys": [{}]},
            orgs=None,
            rate_limit=GitHubCoreRateLimit(remaining=0, reset_at=datetime.now(timezone.utc) - timedelta(seconds=30)),
        )

        assert result.success is False
        assert "any moment now" in result.message
        assert "minute(s)" not in result.message
