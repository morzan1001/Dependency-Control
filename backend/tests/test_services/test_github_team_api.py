"""GitHub team-sync reads: the team/repository check, uncapped pagination, role-tagged members, cache."""

from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest

from app.core.cache import CacheService
from app.services.github import _REPOSITORY_ACCEPT, GitHubService
from tests.mocks.github import make_github_instance

_ORG_URL = "https://api.github.com/organizations/1234"

_ORG_TEAMS = [
    {
        "id": 4711,
        "node_id": "T_kwDOBl2Rp84AEnZn",
        "url": f"{_ORG_URL}/team/4711",
        "html_url": "https://github.com/orgs/acme/teams/payments",
        "name": "Payments",
        "slug": "payments",
        "description": "Payments platform",
        "privacy": "closed",
        "notification_setting": "notifications_enabled",
        "permission": "push",
        "members_url": f"{_ORG_URL}/team/4711/members{{/member}}",
        "repositories_url": f"{_ORG_URL}/team/4711/repos",
        "parent": {
            "id": 42,
            "node_id": "T_kwDOBl2Rp84AEnAA",
            "url": f"{_ORG_URL}/team/42",
            "html_url": "https://github.com/orgs/acme/teams/platform",
            "name": "Platform",
            "slug": "platform",
            "description": "Everything below the product teams",
            "privacy": "closed",
            "notification_setting": "notifications_enabled",
            "permission": "pull",
            "members_url": f"{_ORG_URL}/team/42/members{{/member}}",
            "repositories_url": f"{_ORG_URL}/team/42/repos",
        },
    },
    {
        "id": 8150,
        "node_id": "T_kwDOBl2Rp84AEqLm",
        "url": f"{_ORG_URL}/team/8150",
        "html_url": "https://github.com/orgs/acme/teams/sre",
        "name": "SRE",
        "slug": "sre",
        "description": None,
        "privacy": "secret",
        "permission": "admin",
        "members_url": f"{_ORG_URL}/team/8150/members{{/member}}",
        "repositories_url": f"{_ORG_URL}/team/8150/repos",
        "parent": None,
    },
]

# The repository object GET /orgs/{org}/teams/{slug}/repos/{owner}/{repo} answers with, trimmed to
# the fields the sync reads. `permissions` is the team's access, not the caller's.
_TEAM_REPOSITORY = {
    "id": 987654,
    "node_id": "R_kgDOBl2Rpw",
    "name": "widgets",
    "full_name": "acme/widgets",
    "private": True,
    "role_name": "maintain",
    "permissions": {"pull": True, "triage": True, "push": True, "maintain": True, "admin": False},
}

_ORG_MEMBERSHIPS = [
    {
        "login": "acme",
        "id": 1234,
        "node_id": "O_kgDOBl2Rpw",
        "url": "https://api.github.com/orgs/acme",
        "repos_url": "https://api.github.com/orgs/acme/repos",
        "description": None,
    },
]


def _service() -> GitHubService:
    return GitHubService(make_github_instance(access_token="ghp-secret"))


@pytest.fixture
def fake_cache(monkeypatch):
    """A CacheService backed by an in-memory fakeredis async client."""
    svc = CacheService()
    svc._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    svc._pool = object()
    svc._available = True
    monkeypatch.setattr("app.services.github.cache_service", svc)
    return svc


def _response(status_code: int, payload: dict | None = None) -> MagicMock:
    response = MagicMock(status_code=status_code)
    response.json = MagicMock(return_value=payload)
    return response


class TestTeamRepositoryCheck:
    @pytest.mark.asyncio
    async def test_asks_the_team_whether_it_holds_the_repository(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, _TEAM_REPOSITORY))) as get:
            access = await service.get_team_repository("acme", "payments", "acme", "widgets")

        assert access is True
        assert get.await_args.args[0] == "/orgs/acme/teams/payments/repos/acme/widgets"

    @pytest.mark.asyncio
    async def test_asks_for_the_media_type_that_carries_the_permissions(self, fake_cache):
        """Without it GitHub answers 204, and holding the repository stops looking like a 200."""
        service = _service()
        client = MagicMock()
        client.get = AsyncMock(return_value=_response(200, _TEAM_REPOSITORY))

        class _ClientContext:
            async def __aenter__(self):
                return client

            async def __aexit__(self, *_args):
                return False

        with patch.object(service, "_api_client", return_value=_ClientContext()):
            await service.get_team_repository("acme", "payments", "acme", "widgets")

        assert client.get.await_args.kwargs["headers"]["Accept"] == _REPOSITORY_ACCEPT

    @pytest.mark.asyncio
    async def test_a_404_says_the_team_does_not_hold_it(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(404))):
            assert await service.get_team_repository("acme", "sre", "acme", "widgets") is False

    @pytest.mark.asyncio
    async def test_a_refusal_is_undetermined_rather_than_a_no(self, fake_cache, caplog):
        """Read as a no, a throttled or forbidden check hands the repository to whichever team did answer."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(403))):
            with caplog.at_level("WARNING", logger="app.services.github"):
                access = await service.get_team_repository("acme", "payments", "acme", "widgets")

        assert access is None
        warnings = [record.getMessage() for record in caplog.records if record.levelname == "WARNING"]
        assert len(warnings) == 1, warnings
        assert "403" in warnings[0]

    @pytest.mark.asyncio
    async def test_an_unreachable_api_is_undetermined(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=None)):
            assert await service.get_team_repository("acme", "payments", "acme", "widgets") is None

    @pytest.mark.asyncio
    async def test_the_second_check_is_served_from_the_cache(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, _TEAM_REPOSITORY))) as get:
            await service.get_team_repository("acme", "payments", "acme", "widgets")
            second = await service.get_team_repository("acme", "payments", "acme", "widgets")

        assert second is True
        assert get.await_count == 1

    @pytest.mark.asyncio
    async def test_a_negative_answer_is_cached_too(self, fake_cache):
        """Most bound teams answer no on most repositories; refetching that is what burns the budget."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(404))) as get:
            first = await service.get_team_repository("acme", "sre", "acme", "widgets")
            second = await service.get_team_repository("acme", "sre", "acme", "widgets")

        assert first is False and second is False
        assert get.await_count == 1

    @pytest.mark.asyncio
    async def test_an_undetermined_answer_is_not_cached(self, fake_cache):
        service = _service()
        responses = [_response(500), _response(200, _TEAM_REPOSITORY)]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service.get_team_repository("acme", "payments", "acme", "widgets") is None
            assert await service.get_team_repository("acme", "payments", "acme", "widgets") is True

    @pytest.mark.asyncio
    async def test_one_repository_never_answers_for_another(self, fake_cache):
        service = _service()
        responses = [_response(200, _TEAM_REPOSITORY), _response(404)]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service.get_team_repository("acme", "payments", "acme", "widgets") is True
            assert await service.get_team_repository("acme", "payments", "acme", "gadgets") is False

    @pytest.mark.asyncio
    async def test_one_team_never_answers_for_another(self, fake_cache):
        service = _service()
        responses = [_response(200, _TEAM_REPOSITORY), _response(404)]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service.get_team_repository("acme", "payments", "acme", "widgets") is True
            assert await service.get_team_repository("acme", "sre", "acme", "widgets") is False


class TestOrgTeams:
    @pytest.mark.asyncio
    async def test_are_fetched_uncapped_from_the_org_endpoint(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=[])) as paginated:
            await service.get_org_teams("acme")

        assert paginated.await_args.args[0] == "/orgs/acme/teams"
        assert paginated.await_args.kwargs["max_pages"] is None


class TestOrgTeamCount:
    @pytest.mark.asyncio
    async def test_is_fetched_uncapped_from_the_org_endpoint(self):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_TEAMS)) as paginated:
            assert await service.count_org_teams("acme") == 2

        assert paginated.await_args.args[0] == "/orgs/acme/teams"
        assert paginated.await_args.kwargs["max_pages"] is None

    @pytest.mark.asyncio
    async def test_a_refused_request_stays_none_rather_than_zero(self):
        """The connection test tells "no teams here" from "the API refused" only by this distinction."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=None)):
            assert await service.count_org_teams("acme") is None

    @pytest.mark.asyncio
    async def test_an_organisation_without_teams_counts_zero(self):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=[])):
            assert await service.count_org_teams("acme") == 0

    @pytest.mark.asyncio
    async def test_is_never_served_from_the_cache(self, fake_cache):
        """A connection test reporting a five-minute-old token state, in green, is worse than slow."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_TEAMS)) as paginated:
            await service.count_org_teams("acme")
            await service.count_org_teams("acme")

        assert paginated.await_count == 2

    @pytest.mark.asyncio
    async def test_a_warm_get_org_teams_entry_does_not_answer_the_count(self, fake_cache):
        """A sync minutes earlier leaves that entry warm; a revoked token must still read red."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_TEAMS)) as paginated:
            await service.get_org_teams("acme")
            await service.count_org_teams("acme")

        assert paginated.await_count == 2


class TestTeamMembers:
    @pytest.mark.asyncio
    async def test_carry_the_role_the_query_asked_for(self, fake_cache):
        service = _service()
        pages = {
            "maintainer": [{"login": "ada", "id": 1, "type": "User"}],
            "member": [{"login": "bob", "id": 2, "type": "User"}],
        }

        async def _paginated(endpoint, params=None, max_pages=10):
            return pages[params["role"]]

        with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=_paginated)) as paginated:
            result = await service.get_team_members("acme", "payments", 4711)

        assert result == [
            {"login": "ada", "role": "maintainer"},
            {"login": "bob", "role": "member"},
        ]
        # A capped member list is a team quietly missing people, so both calls must be uncapped.
        assert [call.kwargs["max_pages"] for call in paginated.await_args_list] == [None, None]

    @pytest.mark.asyncio
    async def test_a_failed_page_yields_none_rather_than_half_a_team(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=[[{"login": "ada"}], None])):
            assert await service.get_team_members("acme", "payments", 4711) is None

    @pytest.mark.asyncio
    async def test_a_renamed_slug_still_hits_the_cache_entry_of_the_same_team_id(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=[{"login": "ada"}])) as paginated:
            await service.get_team_members("acme", "payments", 4711)
            renamed = await service.get_team_members("acme", "payments-eu", 4711)

        assert renamed == [{"login": "ada", "role": "maintainer"}, {"login": "ada", "role": "member"}]
        assert paginated.await_count == 2


class TestViewerOrganisations:
    @pytest.mark.asyncio
    async def test_are_fetched_uncapped_from_the_viewer_endpoint(self):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_MEMBERSHIPS)) as paginated:
            assert await service.get_viewer_organisations() == _ORG_MEMBERSHIPS

        assert paginated.await_args.args[0] == "/user/orgs"
        assert paginated.await_args.kwargs["max_pages"] is None

    @pytest.mark.asyncio
    async def test_a_refused_request_stays_none_rather_than_an_empty_list(self):
        """The connection test tells "refused" from "member of nothing" only by this distinction."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=None)):
            assert await service.get_viewer_organisations() is None

    @pytest.mark.asyncio
    async def test_are_never_served_from_the_cache(self, fake_cache):
        """A connection test reporting a five-minute-old token state, in green, is worse than slow."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_MEMBERSHIPS)) as paginated:
            await service.get_viewer_organisations()
            await service.get_viewer_organisations()

        assert paginated.await_count == 2


def _profile(email: str | None) -> MagicMock:
    response = MagicMock(status_code=200)
    response.json = MagicMock(return_value={"login": "ada", "email": email})
    return response


class TestPublicProfileEmail:
    @pytest.mark.asyncio
    async def test_returns_the_public_email(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_profile("ada@example.com"))) as api_get:
            assert await service.get_user_public_email("ada") == "ada@example.com"

        assert api_get.await_args.args[0] == "/users/ada"

    @pytest.mark.asyncio
    async def test_returns_none_when_the_profile_hides_it(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_profile(None))):
            assert await service.get_user_public_email("ada") is None

    @pytest.mark.asyncio
    async def test_a_refusal_is_logged_rather_than_read_as_a_hidden_email(self, fake_cache, caplog):
        service = _service()
        response = MagicMock(status_code=403)
        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)):
            with caplog.at_level("WARNING", logger="app.services.github"):
                assert await service.get_user_public_email("ada") is None

        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1, warnings
        assert "ada" in warnings[0]
        assert "403" in warnings[0]

    @pytest.mark.asyncio
    async def test_an_unknown_login_is_not_worth_a_warning(self, fake_cache, caplog):
        service = _service()
        response = MagicMock(status_code=404)
        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)):
            with caplog.at_level("WARNING", logger="app.services.github"):
                assert await service.get_user_public_email("ghost") is None

        assert [r.getMessage() for r in caplog.records if r.levelname == "WARNING"] == []


class TestPublicProfileEmailCaching:
    """The per-member lookup outnumbers the three list calls; uncached it walks straight past them."""

    @pytest.mark.asyncio
    async def test_the_second_lookup_of_a_login_is_served_from_the_cache(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_profile("ada@example.com"))) as api_get:
            assert await service.get_user_public_email("ada") == "ada@example.com"
            assert await service.get_user_public_email("ada") == "ada@example.com"

        assert api_get.await_count == 1

    @pytest.mark.asyncio
    async def test_a_hidden_email_is_cached_too(self, fake_cache):
        """Bots and private profiles are the routine answer, so refetching them is what burns the budget."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_profile(None))) as api_get:
            assert await service.get_user_public_email("dependabot") is None
            assert await service.get_user_public_email("dependabot") is None

        assert api_get.await_count == 1

    @pytest.mark.asyncio
    async def test_an_unknown_login_is_cached_too(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=MagicMock(status_code=404))) as api_get:
            assert await service.get_user_public_email("ghost") is None
            assert await service.get_user_public_email("ghost") is None

        assert api_get.await_count == 1

    @pytest.mark.asyncio
    async def test_one_login_never_answers_for_another(self, fake_cache):
        service = _service()

        async def _by_login(endpoint, params=None):
            return _profile(f"{endpoint.rsplit('/', 1)[1]}@example.com")

        with patch.object(service, "_api_get", new=AsyncMock(side_effect=_by_login)):
            assert await service.get_user_public_email("ada") == "ada@example.com"
            assert await service.get_user_public_email("bob") == "bob@example.com"

    @pytest.mark.asyncio
    async def test_a_refusal_is_not_cached(self, fake_cache):
        """A throttled 403 held for the TTL would strip email matching from every later job of the run."""
        service = _service()
        responses = [MagicMock(status_code=403), _profile("ada@example.com")]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service.get_user_public_email("ada") is None
            assert await service.get_user_public_email("ada") == "ada@example.com"

    @pytest.mark.asyncio
    async def test_a_second_instance_does_not_read_the_first_ones_entry(self, fake_cache):
        """Two instances are two tokens against two user namespaces; GHES logins are not github.com logins."""
        first = GitHubService(make_github_instance(id="gh-1", access_token="ghp-secret"))
        second = GitHubService(make_github_instance(id="gh-2", access_token="ghp-other"))

        with patch.object(first, "_api_get", new=AsyncMock(return_value=_profile("ada@example.com"))):
            assert await first.get_user_public_email("ada") == "ada@example.com"
        with patch.object(second, "_api_get", new=AsyncMock(return_value=_profile("ada@ghes.internal"))):
            assert await second.get_user_public_email("ada") == "ada@ghes.internal"
