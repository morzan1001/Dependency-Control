"""GitHub team-sync reads: the team/repository check, uncapped pagination, role-tagged members, cache."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest

from app.core.cache import CacheService
from app.services.github import _GITHUB_ORG_WALK_CONCURRENCY, _REPOSITORY_ACCEPT, GitHubService
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


_ACCESS_LEVELS = ("pull", "triage", "push", "maintain", "admin")


def _held_repository(full_name: str, access: str = "push", **fields) -> dict:
    """One entry of GET /orgs/{org}/teams/{slug}/repos. GitHub reports the team's permissions
    cumulatively, so a team with maintain also reads as push."""
    reached = _ACCESS_LEVELS.index(access)
    permissions = {level: index <= reached for index, level in enumerate(_ACCESS_LEVELS)}
    return {"full_name": full_name, "permissions": permissions, **fields}


class TestOrgRepositoryMap:
    """Asking a repository for its teams needs admin on it, so the map is walked team by team."""

    @staticmethod
    def _listings(held: dict[str, list | None]):
        """``held`` maps a team slug to the repositories it holds — a name, or a name and the
        access the team has to it — and to None for a listing that went unanswered."""

        def _entry(repository):
            if not isinstance(repository, tuple):
                return _held_repository(repository)
            full_name, access, *fields = repository
            return _held_repository(full_name, access, **(fields[0] if fields else {}))

        async def _paginated(endpoint, params=None, max_pages=10):
            slug = endpoint.split("/")[4]
            repositories = held.get(slug)
            return None if repositories is None else [_entry(repository) for repository in repositories]

        return AsyncMock(side_effect=_paginated)

    @pytest.mark.asyncio
    async def test_is_walked_team_by_team_and_uncapped(self, fake_cache):
        service = _service()
        listings = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_get_paginated", new=listings):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) == {"acme/widgets": [4711]}

        assert [call.args[0] for call in listings.await_args_list] == [
            "/orgs/acme/teams/payments/repos",
            "/orgs/acme/teams/sre/repos",
        ]
        assert [call.kwargs["max_pages"] for call in listings.await_args_list] == [None, None]

    @pytest.mark.asyncio
    async def test_names_every_team_holding_one_repository(self, fake_cache):
        service = _service()
        listings = self._listings({"payments": ["acme/widgets"], "sre": ["acme/widgets", "acme/gadgets"]})

        with patch.object(service, "_api_get_paginated", new=listings):
            repo_map = await service.get_org_repository_map("acme", _ORG_TEAMS)

        assert repo_map == {"acme/widgets": [4711, 8150], "acme/gadgets": [8150]}

    @pytest.mark.asyncio
    async def test_the_full_names_are_lower_cased_so_an_oidc_claim_matches(self, fake_cache):
        service = _service()

        with patch.object(service, "_api_get_paginated", new=self._listings({"payments": ["Acme/Widgets"], "sre": []})):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    async def test_a_team_that_went_unanswered_leaves_the_whole_map_undetermined(self, fake_cache):
        """Half a walk names the wrong holders: the teams it did not reach read as holding nothing."""
        service = _service()

        with patch.object(service, "_api_get_paginated", new=self._listings({"payments": ["acme/widgets"]})):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("access", ["push", "maintain", "admin"])
    async def test_a_team_that_may_write_holds_the_repository(self, fake_cache, access):
        service = _service()
        listings = self._listings({"payments": [("acme/widgets", access)], "sre": []})

        with patch.object(service, "_api_get_paginated", new=listings):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("access", ["pull", "triage"])
    async def test_a_team_that_may_only_read_does_not_hold_it(self, fake_cache, access):
        """An "all-org-members" group has pull on everything; read as ownership it owns the estate."""
        service = _service()
        listings = self._listings({"payments": [("acme/widgets", access)], "sre": [("acme/widgets", "push")]})

        with patch.object(service, "_api_get_paginated", new=listings):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) == {"acme/widgets": [8150]}

    @pytest.mark.asyncio
    async def test_an_archived_fork_is_held_by_the_team_that_may_write_to_it(self, fake_cache):
        """Neither flag says anything about who owns the repository, and a scan arriving for one is
        a repository somebody works on."""
        service = _service()
        listings = self._listings(
            {"payments": [("acme/widgets", "push", {"archived": True, "fork": True})], "sre": []}
        )

        with patch.object(service, "_api_get_paginated", new=listings):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    async def test_a_listing_that_does_not_say_what_the_access_is_leaves_the_map_undetermined(self, fake_cache, caplog):
        """Read as read-only it would retire the owners of every repository of the organisation."""
        service = _service()

        async def _paginated(endpoint, params=None, max_pages=10):
            return [{"full_name": "acme/widgets"}]

        with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=_paginated)):
            with caplog.at_level("WARNING", logger="app.services.github"):
                assert await service.get_org_repository_map("acme", _ORG_TEAMS) is None

        assert any("payments" in record.getMessage() for record in caplog.records if record.levelname == "WARNING")

    @pytest.mark.asyncio
    async def test_the_walk_is_paid_once_a_ttl_rather_than_once_an_ingest(self, fake_cache):
        service = _service()
        listings = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_get_paginated", new=listings):
            first = await service.get_org_repository_map("acme", _ORG_TEAMS)
            second = await service.get_org_repository_map("acme", _ORG_TEAMS)

        assert first == {"acme/widgets": [4711]}
        assert second == first
        assert listings.await_count == 2

    @pytest.mark.asyncio
    async def test_an_organisation_whose_teams_hold_nothing_is_cached_too(self, fake_cache):
        service = _service()
        listings = self._listings({"payments": [], "sre": []})

        with patch.object(service, "_api_get_paginated", new=listings):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) == {}
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) == {}

        assert listings.await_count == 2

    @pytest.mark.asyncio
    async def test_an_undetermined_walk_never_reads_back_as_an_organisation_holding_nothing(self, fake_cache):
        """What the cache stores for a failed walk is a bare {}, and that is the shape of a map in
        which no team holds anything — the answer that retires every owner."""
        service = _service()
        attempts = [self._listings({"payments": ["acme/widgets"]}), self._listings({"payments": [], "sre": []})]

        with patch.object(service, "_api_get_paginated", new=attempts[0]):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) is None
        with patch.object(service, "_api_get_paginated", new=attempts[1]):
            assert await service.get_org_repository_map("acme", _ORG_TEAMS) is None

    @pytest.mark.asyncio
    async def test_a_walk_that_failed_is_not_walked_again_by_the_next_ingest(self, fake_cache):
        """204 requests a walk: retrying it per ingest is what exhausts the hourly budget, and an
        exhausted token answers 403, which leaves every project undetermined for the hour anyway."""
        service = _service()
        second = self._listings({"payments": [], "sre": []})

        with patch.object(service, "_api_get_paginated", new=self._listings({"payments": ["acme/widgets"]})):
            await service.get_org_repository_map("acme", _ORG_TEAMS)
        with patch.object(service, "_api_get_paginated", new=second):
            await service.get_org_repository_map("acme", _ORG_TEAMS)

        assert second.await_count == 0

    @pytest.mark.asyncio
    async def test_a_walk_that_outlasts_its_budget_is_recorded_rather_than_abandoned(self, fake_cache, caplog):
        service = _service()

        async def _never_answers(_endpoint, params=None, max_pages=10):
            await asyncio.sleep(60)
            raise AssertionError("the walk should have been abandoned")

        with patch("app.services.github._GITHUB_ORG_WALK_TIMEOUT", 0.05):
            with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=_never_answers)):
                with caplog.at_level("WARNING", logger="app.services.github"):
                    assert await service.get_org_repository_map("acme", _ORG_TEAMS) is None
            second = self._listings({"payments": [], "sre": []})
            with patch.object(service, "_api_get_paginated", new=second):
                assert await service.get_org_repository_map("acme", _ORG_TEAMS) is None

        assert second.await_count == 0
        assert any("acme" in record.getMessage() for record in caplog.records if record.levelname == "WARNING")

    @pytest.mark.asyncio
    async def test_two_ingests_arriving_together_walk_the_organisation_once(self, fake_cache):
        """The jobs of one workflow run arrive together; eight walks of the largest organisation
        here are 1632 requests of a 5000-per-hour budget."""
        service = _service()
        listings = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_get_paginated", new=listings):
            results = await asyncio.gather(
                service.get_org_repository_map("acme", _ORG_TEAMS),
                service.get_org_repository_map("acme", _ORG_TEAMS),
            )

        assert results == [{"acme/widgets": [4711]}, {"acme/widgets": [4711]}]
        assert listings.await_count == 2

    @pytest.mark.asyncio
    async def test_one_organisation_never_answers_for_another(self, fake_cache):
        service = _service()
        listings = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_get_paginated", new=listings):
            await service.get_org_repository_map("acme", _ORG_TEAMS)
            await service.get_org_repository_map("acme-labs", _ORG_TEAMS)

        assert listings.await_count == 4

    @pytest.mark.asyncio
    async def test_the_listings_do_not_add_up(self, fake_cache):
        """A cold map on the largest organisation here is 204 listings; in sequence they would
        outlast the resolution budget the ingest is bounded by."""
        service = _service()
        org_teams = [{"id": 1000 + index, "slug": f"t{index}", "parent": None} for index in range(64)]

        async def _slow(_endpoint, params=None, max_pages=10):
            await asyncio.sleep(0.02)
            return []

        with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=_slow)):
            started = time.perf_counter()
            assert await service.get_org_repository_map("acme", org_teams) == {}
            elapsed = time.perf_counter() - started

        assert elapsed < 0.02 * 64 / 4

    @staticmethod
    def _peak_tracker():
        """Counts the requests in flight across every walk, which is what GitHub sees."""
        state = {"in_flight": 0, "peak": 0}

        async def _tracked(_endpoint, params=None, max_pages=10):
            state["in_flight"] += 1
            state["peak"] = max(state["peak"], state["in_flight"])
            await asyncio.sleep(0.01)
            state["in_flight"] -= 1
            return []

        return state, AsyncMock(side_effect=_tracked)

    @pytest.mark.asyncio
    async def test_the_walk_stays_below_the_concurrency_github_tolerates(self, fake_cache):
        service = _service()
        org_teams = [{"id": 1000 + index, "slug": f"t{index}", "parent": None} for index in range(64)]
        state, tracked = self._peak_tracker()

        with patch.object(service, "_api_get_paginated", new=tracked):
            await service.get_org_repository_map("acme", org_teams)

        assert state["peak"] == _GITHUB_ORG_WALK_CONCURRENCY

    @pytest.mark.asyncio
    async def test_the_limit_holds_across_the_walks_of_concurrent_ingests(self, fake_cache):
        """A limit each walk holds on its own bounds no ingest against another: eight of them
        measured 112 requests in flight against a limit of 16."""
        service = _service()
        org_teams = [{"id": 1000 + index, "slug": f"t{index}", "parent": None} for index in range(64)]
        state, tracked = self._peak_tracker()

        with patch.object(service, "_api_get_paginated", new=tracked):
            await asyncio.gather(*(service.get_org_repository_map(f"acme-{index}", org_teams) for index in range(4)))

        assert state["peak"] <= _GITHUB_ORG_WALK_CONCURRENCY

    @pytest.mark.asyncio
    async def test_a_team_the_listing_cannot_address_is_left_out_rather_than_fatal(self, fake_cache):
        service = _service()
        org_teams = [*_ORG_TEAMS, {"id": None, "slug": "broken", "parent": None}]
        listings = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_get_paginated", new=listings):
            assert await service.get_org_repository_map("acme", org_teams) == {"acme/widgets": [4711]}

        assert listings.await_count == 2


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
