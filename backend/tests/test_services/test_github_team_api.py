"""GitHub team-sync reads: the team/repository check, uncapped pagination, role-tagged members, cache."""

import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest

from app.core.cache import CacheService
from app.core.constants import GITHUB_API_URL, GITHUB_TEAM_SYNC_CACHE_TTL
from app.repositories.users import UserRepository
from app.services.github import (
    _GITHUB_ORG_WALK_CONCURRENCY,
    _REPOSITORY_ACCEPT,
    GitHubService,
    _HolderBinding,
    _org_walk_gate,
    build_team_slug_map,
)
from tests.mocks.fake_mongo import FakeDatabase
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

_KEPT_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "parent": {"name": "Platform"}},
    {"id": 8150, "slug": "sre", "name": "SRE", "parent": None},
]

_SLUG_MAP = {4711: "payments", 8150: "sre"}

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

_REPOSITORY = {"id": 987654, "name": "widgets", "full_name": "acme/widgets", "private": True}
_NOT_FOUND = {
    "message": "Not Found",
    "documentation_url": "https://docs.github.com/rest/repos/repos#get-a-repository",
    "status": "404",
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


def _service(instance_id: str = "test-github-instance-id") -> GitHubService:
    return GitHubService(make_github_instance(id=instance_id, access_token="ghp-secret"))


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


def _page(items: list[dict], has_next: bool = False) -> MagicMock:
    response = _response(200, items)
    response.headers = {"link": '<https://api.github.com/x?page=2>; rel="next"'} if has_next else {}
    return response


class _GitHubApi:
    """api.github.com behind ``_api_client``: answers each GET by path and records what it was asked."""

    def __init__(self, answer):
        self._answer = answer
        self.requests: list[tuple[str, dict]] = []
        self.in_flight = 0
        self.peak = 0

    @asynccontextmanager
    async def client(self):
        yield self

    async def get(self, url, headers=None, params=None):
        path = url.removeprefix(GITHUB_API_URL)
        self.requests.append((path, dict(params or {})))
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            return await self._answer(path, params or {})
        finally:
            self.in_flight -= 1

    @property
    def paths(self) -> list[str]:
        return [path for path, _params in self.requests]


async def _cached_ttls(cache: CacheService) -> list[int]:
    return [await cache._client.ttl(key) for key in await cache._client.keys("*") if "lock:" not in key]


class TestTeamRepositoryCheck:
    @pytest.mark.asyncio
    async def test_asks_the_team_whether_it_holds_the_repository(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, _TEAM_REPOSITORY))) as get:
            access = await service.team_writes_to_repository("acme", "payments", 4711, "widgets")

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
            await service.team_writes_to_repository("acme", "payments", 4711, "widgets")

        assert client.get.await_args.kwargs["headers"]["Accept"] == _REPOSITORY_ACCEPT

    @pytest.mark.asyncio
    async def test_read_only_access_is_not_holding_it(self, fake_cache):
        """The endpoint answers 200 on pull as readily as on admin, so the status is a permission
        check and not a write check. A group with read-everything would otherwise own the estate."""
        service = _service()
        reader = {**_TEAM_REPOSITORY, "role_name": "read", "permissions": {"pull": True, "triage": True}}
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, reader))):
            assert await service.team_writes_to_repository("acme", "auditors", 2323, "widgets") is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("level", ["push", "maintain", "admin"])
    async def test_write_access_or_better_is_holding_it(self, fake_cache, level):
        service = _service()
        writer = {**_TEAM_REPOSITORY, "permissions": {"pull": True, level: True}}
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, writer))):
            assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is True

    @pytest.mark.asyncio
    async def test_a_body_that_names_no_permissions_is_undetermined(self, fake_cache, caplog):
        """Read as read-only it would retire the owners of a whole organisation."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, {"full_name": "acme/w"}))):
            with caplog.at_level("WARNING", logger="app.services.github"):
                assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is None

        assert any("payments" in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_a_body_that_is_not_a_document_is_undetermined(self, fake_cache):
        service = _service()
        unreadable = MagicMock(status_code=200)
        unreadable.json = MagicMock(side_effect=ValueError("not json"))
        with patch.object(service, "_api_get", new=AsyncMock(return_value=unreadable)):
            assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is None

    @pytest.mark.asyncio
    async def test_a_read_only_answer_is_cached_as_the_no_it_is(self, fake_cache):
        service = _service()
        reader = {**_TEAM_REPOSITORY, "permissions": {"pull": True}}
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, reader))) as get:
            first = await service.team_writes_to_repository("acme", "auditors", 2323, "widgets")
            second = await service.team_writes_to_repository("acme", "auditors", 2323, "widgets")

        assert first is False and second is False
        assert get.await_count == 1

    @pytest.mark.asyncio
    async def test_a_404_says_the_team_does_not_hold_it(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(404))):
            assert await service.team_writes_to_repository("acme", "sre", 8150, "widgets") is False

    @pytest.mark.asyncio
    async def test_a_refusal_is_undetermined_rather_than_a_no(self, fake_cache, caplog):
        """Read as a no, a throttled or forbidden check hands the repository to whichever team did answer."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(403))):
            with caplog.at_level("WARNING", logger="app.services.github"):
                access = await service.team_writes_to_repository("acme", "payments", 4711, "widgets")

        assert access is None
        warnings = [record.getMessage() for record in caplog.records if record.levelname == "WARNING"]
        assert len(warnings) == 1, warnings
        assert "403" in warnings[0]

    @pytest.mark.asyncio
    async def test_an_unreachable_api_is_undetermined(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=None)):
            assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is None

    @pytest.mark.asyncio
    async def test_the_second_check_is_served_from_the_cache(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, _TEAM_REPOSITORY))) as get:
            await service.team_writes_to_repository("acme", "payments", 4711, "widgets")
            second = await service.team_writes_to_repository("acme", "payments", 4711, "widgets")

        assert second is True
        assert get.await_count == 1

    @pytest.mark.asyncio
    async def test_a_negative_answer_is_cached_too(self, fake_cache):
        """Most bound teams answer no on most repositories; refetching that is what burns the budget."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(404))) as get:
            first = await service.team_writes_to_repository("acme", "sre", 8150, "widgets")
            second = await service.team_writes_to_repository("acme", "sre", 8150, "widgets")

        assert first is False and second is False
        assert get.await_count == 1

    @pytest.mark.asyncio
    async def test_an_undetermined_answer_is_not_cached(self, fake_cache):
        service = _service()
        responses = [_response(500), _response(200, _TEAM_REPOSITORY)]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is None
            assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is True

    @pytest.mark.asyncio
    async def test_one_repository_never_answers_for_another(self, fake_cache):
        service = _service()
        responses = [_response(200, _TEAM_REPOSITORY), _response(404)]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is True
            assert await service.team_writes_to_repository("acme", "payments", 4711, "gadgets") is False

    @pytest.mark.asyncio
    async def test_one_team_never_answers_for_another(self, fake_cache):
        service = _service()
        responses = [_response(200, _TEAM_REPOSITORY), _response(404)]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service.team_writes_to_repository("acme", "payments", 4711, "widgets") is True
            assert await service.team_writes_to_repository("acme", "sre", 8150, "widgets") is False

    @pytest.mark.asyncio
    async def test_the_checks_share_the_instance_gate(self, fake_cache):
        """A workflow run of eight jobs asking about every bound team put 960 requests in flight."""
        service = _service()

        async def _answer(_path, _params):
            await asyncio.sleep(0.01)
            return _response(200, _TEAM_REPOSITORY)

        api = _GitHubApi(_answer)
        with patch.object(service, "_api_client", new=api.client):
            await asyncio.gather(
                *(service.team_writes_to_repository("acme", f"t{index}", index, "widgets") for index in range(40))
            )

        assert api.peak == _GITHUB_ORG_WALK_CONCURRENCY

    @pytest.mark.asyncio
    async def test_a_renamed_slug_still_hits_the_answer_of_the_same_team_id(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, _TEAM_REPOSITORY))) as get:
            await service.team_writes_to_repository("acme", "payments", 4711, "widgets")
            renamed = await service.team_writes_to_repository("acme", "payments-eu", 4711, "widgets")

        assert renamed is True
        assert get.await_count == 1

    @pytest.mark.asyncio
    async def test_a_team_taking_over_a_freed_slug_never_reads_the_answer_of_its_previous_holder(self, fake_cache):
        service = _service()
        answers = [_response(200, _TEAM_REPOSITORY), _response(404, {"message": "Not Found"})]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=answers)):
            assert await service.team_writes_to_repository("acme", "payments", 17, "widgets") is True
            assert await service.team_writes_to_repository("acme", "payments", 42, "widgets") is False


class TestRepositoryVisibility:
    @pytest.mark.asyncio
    async def test_a_repository_github_describes_is_visible(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(200, _REPOSITORY))) as get:
            assert await service._repository_visible("acme", "widgets") is True

        get.assert_awaited_once_with("/repos/acme/widgets")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [404, 403, 301])
    async def test_a_repository_github_will_not_describe_is_not(self, fake_cache, status):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(status, _NOT_FOUND))):
            assert await service._repository_visible("acme", "widgets") is False

    @pytest.mark.asyncio
    async def test_an_unreachable_api_is_undetermined(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=None)):
            assert await service._repository_visible("acme", "widgets") is None

    @pytest.mark.asyncio
    async def test_the_answer_is_cached_for_the_sync_ttl(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_response(404, _NOT_FOUND))) as get:
            await service._repository_visible("acme", "widgets")
            assert await service._repository_visible("acme", "widgets") is False

        assert get.await_count == 1
        assert 0 < max(await _cached_ttls(fake_cache)) <= GITHUB_TEAM_SYNC_CACHE_TTL


class TestOrgTeams:
    """Every GitHub ingest resolves its owner through this listing, so all of it is load-bearing:
    what it answers with, how far it reads, what it makes of a refusal, and who its entry answers
    for."""

    @pytest.mark.asyncio
    async def test_are_fetched_uncapped_from_the_org_endpoint(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_TEAMS)) as paginated:
            assert await service.get_org_teams("acme") == _KEPT_TEAMS

        assert paginated.await_args.args[0] == "/orgs/acme/teams"
        # A capped listing is an organisation quietly missing teams, and a team the listing omits
        # reads as one the organisation dissolved.
        assert paginated.await_args.kwargs["max_pages"] is None

    @pytest.mark.asyncio
    async def test_an_organisation_without_teams_is_an_empty_listing(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=[])):
            assert await service.get_org_teams("acme") == []

    @pytest.mark.asyncio
    async def test_an_unanswered_listing_is_none_rather_than_an_organisation_without_teams(self, fake_cache):
        """Read as empty, a refused listing retires the owner of every project in the organisation."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=None)):
            assert await service.get_org_teams("acme") is None

    @pytest.mark.asyncio
    async def test_an_unanswered_listing_is_not_asked_again_inside_the_listing_ttl(self, fake_cache):
        """A throttled token asked again by every job of the run stays throttled; an hour of it
        would hold the whole organisation undetermined long after GitHub answers again."""
        service = _service()

        async def _answer(_path, _params):
            return _response(403, {"message": "API rate limit exceeded for installation ID 1234."})

        api = _GitHubApi(_answer)
        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_teams("acme") is None
            assert await service.get_org_teams("acme") is None

        assert len(api.requests) == 1
        assert 0 < max(await _cached_ttls(fake_cache)) <= GITHUB_TEAM_SYNC_CACHE_TTL

    @pytest.mark.asyncio
    async def test_two_ingests_arriving_together_list_the_teams_once(self, fake_cache):
        service = _service()

        async def _answer(_path, _params):
            await asyncio.sleep(0.02)
            return _page(_ORG_TEAMS)

        api = _GitHubApi(_answer)
        with patch.object(service, "_api_client", new=api.client):
            await asyncio.gather(service.get_org_teams("acme"), service.get_org_teams("acme"))

        assert api.paths == ["/orgs/acme/teams"]

    @pytest.mark.asyncio
    async def test_only_what_the_sync_reads_of_a_team_is_kept(self, fake_cache):
        """Each ingest reads the listing back out of the cache, and most of a team object is URLs."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_TEAMS)):
            teams = await service.get_org_teams("acme")

        assert teams == _KEPT_TEAMS

    @pytest.mark.asyncio
    async def test_the_second_read_is_served_from_the_cache_whole(self, fake_cache):
        """The jobs of one workflow run arrive together, and each would otherwise page the listing
        again. What comes back out has to be the listing, parents and all: the parent is what tells
        two same-named teams apart."""
        service = _service()
        with patch.object(service, "_api_get_paginated", new=AsyncMock(return_value=_ORG_TEAMS)) as paginated:
            await service.get_org_teams("acme")
            second = await service.get_org_teams("acme")

        assert second == _KEPT_TEAMS
        assert paginated.await_count == 1

    @pytest.mark.asyncio
    async def test_one_organisation_never_answers_for_another(self, fake_cache):
        service = _service()
        responses = [_ORG_TEAMS, []]
        with patch.object(service, "_api_get_paginated", new=AsyncMock(side_effect=responses)) as paginated:
            assert await service.get_org_teams("acme") == _KEPT_TEAMS
            assert await service.get_org_teams("acme-labs") == []

        assert [call.args[0] for call in paginated.await_args_list] == [
            "/orgs/acme/teams",
            "/orgs/acme-labs/teams",
        ]

    @pytest.mark.asyncio
    async def test_one_instance_never_answers_for_another(self, fake_cache):
        """Two instances can both be configured for the same organisation name, and each reads it
        through its own token."""
        responses = [_ORG_TEAMS, []]
        with patch.object(GitHubService, "_api_get_paginated", new=AsyncMock(side_effect=responses)):
            assert await _service("gh-1").get_org_teams("acme") == _KEPT_TEAMS
            assert await _service("gh-2").get_org_teams("acme") == []


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
    def _listings(held: dict[str, list | None], delay: float = 0.0, released: asyncio.Event | None = None):
        """GET /orgs/{org}/teams/{slug}/repos, one page per team. ``held`` maps a team slug to the
        repositories it holds — a name, or a name and the access the team has to it — and to None
        for a listing GitHub refuses."""

        def _entry(repository):
            if isinstance(repository, dict):
                return repository
            if not isinstance(repository, tuple):
                return _held_repository(repository)
            full_name, access, *fields = repository
            return _held_repository(full_name, access, **(fields[0] if fields else {}))

        async def _answer(path, _params):
            if released is not None:
                await released.wait()
            await asyncio.sleep(delay)
            repositories = held.get(path.split("/")[4])
            if repositories is None:
                return _response(403, {"message": "Resource not accessible by integration"})
            return _page([_entry(repository) for repository in repositories])

        return _GitHubApi(_answer)

    @staticmethod
    def _teams(count: int, prefix: str = "t") -> dict[int, str]:
        return {1000 + index: f"{prefix}{index}" for index in range(count)}

    @pytest.mark.asyncio
    async def test_is_walked_team_by_team(self, fake_cache):
        service = _service()
        api = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) == {"acme/widgets": [4711]}

        assert api.paths == ["/orgs/acme/teams/payments/repos", "/orgs/acme/teams/sre/repos"]

    @pytest.mark.asyncio
    async def test_a_team_holding_more_than_ten_pages_is_read_to_the_end(self, fake_cache):
        """A capped listing reads the repositories past the cap as ones the team does not hold."""
        service = _service()

        async def _answer(_path, params):
            page = params["page"]
            return _page([_held_repository(f"acme/repo-{page}")], has_next=page < 12)

        api = _GitHubApi(_answer)
        with patch.object(service, "_api_client", new=api.client):
            repo_map = await service.get_org_repository_map("acme", {4711: "payments"})

        assert repo_map is not None and "acme/repo-12" in repo_map

    @pytest.mark.asyncio
    async def test_names_every_team_holding_one_repository(self, fake_cache):
        service = _service()
        api = self._listings({"payments": ["acme/widgets"], "sre": ["acme/widgets", "acme/gadgets"]})

        with patch.object(service, "_api_client", new=api.client):
            repo_map = await service.get_org_repository_map("acme", _SLUG_MAP)

        assert repo_map == {"acme/widgets": [4711, 8150], "acme/gadgets": [8150]}

    @pytest.mark.asyncio
    async def test_the_full_names_are_lower_cased_so_an_oidc_claim_matches(self, fake_cache):
        service = _service()

        with patch.object(service, "_api_client", new=self._listings({"payments": ["Acme/Widgets"], "sre": []}).client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    async def test_a_team_that_went_unanswered_leaves_the_whole_map_undetermined(self, fake_cache):
        """Half a walk names the wrong holders: the teams it did not reach read as holding nothing."""
        service = _service()

        with patch.object(service, "_api_client", new=self._listings({"payments": ["acme/widgets"]}).client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("access", ["push", "maintain", "admin"])
    async def test_a_team_that_may_write_holds_the_repository(self, fake_cache, access):
        service = _service()
        api = self._listings({"payments": [("acme/widgets", access)], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("access", ["pull", "triage"])
    async def test_a_team_that_may_only_read_does_not_hold_it(self, fake_cache, access):
        """An "all-org-members" group has pull on everything; read as ownership it owns the estate."""
        service = _service()
        api = self._listings({"payments": [("acme/widgets", access)], "sre": [("acme/widgets", "push")]})

        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) == {"acme/widgets": [8150]}

    @pytest.mark.asyncio
    async def test_an_archived_fork_is_held_by_the_team_that_may_write_to_it(self, fake_cache):
        """Neither flag says anything about who owns the repository, and a scan arriving for one is
        a repository somebody works on."""
        service = _service()
        api = self._listings({"payments": [("acme/widgets", "push", {"archived": True, "fork": True})], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    async def test_a_listing_that_does_not_say_what_the_access_is_leaves_the_map_undetermined(self, fake_cache, caplog):
        """Read as read-only it would retire the owners of every repository of the organisation."""
        service = _service()
        api = self._listings({"payments": [{"full_name": "acme/widgets"}], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            with caplog.at_level("WARNING", logger="app.services.github"):
                assert await service.get_org_repository_map("acme", _SLUG_MAP) is None

        assert any("payments" in record.getMessage() for record in caplog.records if record.levelname == "WARNING")

    @pytest.mark.asyncio
    async def test_the_walk_is_paid_once_a_ttl_rather_than_once_an_ingest(self, fake_cache):
        service = _service()
        api = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            first = await service.get_org_repository_map("acme", _SLUG_MAP)
            second = await service.get_org_repository_map("acme", _SLUG_MAP)

        assert first == {"acme/widgets": [4711]}
        assert second == first
        assert len(api.requests) == 2

    @pytest.mark.asyncio
    async def test_an_organisation_whose_teams_hold_nothing_is_cached_too(self, fake_cache):
        service = _service()
        api = self._listings({"payments": [], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) == {}
            assert await service.get_org_repository_map("acme", _SLUG_MAP) == {}

        assert len(api.requests) == 2

    @pytest.mark.asyncio
    async def test_an_undetermined_walk_never_reads_back_as_an_organisation_holding_nothing(self, fake_cache):
        """What the cache stores for a failed walk is a bare {}, and that is the shape of a map in
        which no team holds anything — the answer that retires every owner."""
        service = _service()

        with patch.object(service, "_api_client", new=self._listings({"payments": ["acme/widgets"]}).client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) is None
        with patch.object(service, "_api_client", new=self._listings({"payments": [], "sre": []}).client):
            assert await service.get_org_repository_map("acme", _SLUG_MAP) is None

    @pytest.mark.asyncio
    async def test_a_walk_that_failed_is_not_walked_again_by_the_next_ingest(self, fake_cache):
        """204 requests a walk: retrying it per ingest is what exhausts the hourly budget, and an
        exhausted token answers 403, which leaves every project undetermined for the hour anyway."""
        service = _service()
        second = self._listings({"payments": [], "sre": []})

        with patch.object(service, "_api_client", new=self._listings({"payments": ["acme/widgets"]}).client):
            await service.get_org_repository_map("acme", _SLUG_MAP)
        with patch.object(service, "_api_client", new=second.client):
            await service.get_org_repository_map("acme", _SLUG_MAP)

        assert second.requests == []

    @pytest.mark.asyncio
    async def test_a_walk_that_outlasts_its_budget_is_recorded_rather_than_abandoned(self, fake_cache, caplog):
        service = _service()

        async def _never_answers(_path, _params):
            await asyncio.sleep(60)
            raise AssertionError("the walk should have been abandoned")

        with patch("app.services.github._GITHUB_ORG_WALK_TIMEOUT", 0.05):
            with patch.object(service, "_api_client", new=_GitHubApi(_never_answers).client):
                with caplog.at_level("WARNING", logger="app.services.github"):
                    assert await service.get_org_repository_map("acme", _SLUG_MAP) is None
            second = self._listings({"payments": [], "sre": []})
            with patch.object(service, "_api_client", new=second.client):
                assert await service.get_org_repository_map("acme", _SLUG_MAP) is None

        assert second.requests == []
        assert any("acme" in record.getMessage() for record in caplog.records if record.levelname == "WARNING")

    @pytest.mark.asyncio
    async def test_two_ingests_arriving_together_walk_the_organisation_once(self, fake_cache):
        """The jobs of one workflow run arrive together; eight walks of the largest organisation
        here are 1632 requests of a 5000-per-hour budget."""
        service = _service()
        api = self._listings({"payments": ["acme/widgets"], "sre": []}, delay=0.02)

        with patch.object(service, "_api_client", new=api.client):
            results = await asyncio.gather(
                service.get_org_repository_map("acme", _SLUG_MAP),
                service.get_org_repository_map("acme", _SLUG_MAP),
            )

        assert results == [{"acme/widgets": [4711]}, {"acme/widgets": [4711]}]
        assert len(api.requests) == 2

    @pytest.mark.asyncio
    async def test_one_organisation_never_answers_for_another(self, fake_cache):
        service = _service()
        api = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            await service.get_org_repository_map("acme", _SLUG_MAP)
            await service.get_org_repository_map("acme-labs", _SLUG_MAP)

        assert len(api.requests) == 4

    @pytest.mark.asyncio
    async def test_the_listings_do_not_add_up(self, fake_cache):
        """A cold map on the largest organisation here is 204 listings; in sequence they would
        outlast the resolution budget the ingest is bounded by."""
        service = _service()
        api = self._listings({slug: [] for slug in self._teams(64).values()}, delay=0.02)

        with patch.object(service, "_api_client", new=api.client):
            started = time.perf_counter()
            assert await service.get_org_repository_map("acme", self._teams(64)) == {}
            elapsed = time.perf_counter() - started

        assert elapsed < 0.02 * 64 / 4

    @pytest.mark.asyncio
    async def test_the_walk_stays_below_the_concurrency_github_tolerates(self, fake_cache):
        service = _service()
        api = self._listings({slug: [] for slug in self._teams(64).values()}, delay=0.01)

        with patch.object(service, "_api_client", new=api.client):
            await service.get_org_repository_map("acme", self._teams(64))

        assert api.peak == _GITHUB_ORG_WALK_CONCURRENCY

    @pytest.mark.asyncio
    async def test_the_limit_holds_across_the_walks_of_concurrent_ingests(self, fake_cache):
        """A limit each walk holds on its own bounds no ingest against another: eight of them
        measured 112 requests in flight against a limit of 16."""
        service = _service()
        api = self._listings({slug: [] for slug in self._teams(64).values()}, delay=0.01)

        with patch.object(service, "_api_client", new=api.client):
            await asyncio.gather(
                *(service.get_org_repository_map(f"acme-{index}", self._teams(64)) for index in range(4))
            )

        assert api.peak <= _GITHUB_ORG_WALK_CONCURRENCY

    @pytest.mark.asyncio
    async def test_a_team_the_listing_cannot_address_is_left_out_rather_than_fatal(self, fake_cache):
        service = _service()
        slug_map = build_team_slug_map([*_ORG_TEAMS, {"id": None, "slug": "broken", "parent": None}])
        api = self._listings({"payments": ["acme/widgets"], "sre": []})

        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_repository_map("acme", slug_map) == {"acme/widgets": [4711]}

        assert len(api.requests) == 2

    @pytest.mark.asyncio
    async def test_a_team_listed_twice_is_walked_once(self, fake_cache):
        """A page-numbered listing repeats a team that moved while it was read; walked twice it
        holds the repository twice and counts twice against the project's owner budget."""
        service = _service()
        api = self._listings({"payments": ["acme/widgets"]})

        with patch.object(service, "_api_client", new=api.client):
            repo_map = await service.get_org_repository_map("acme", build_team_slug_map([_ORG_TEAMS[0], _ORG_TEAMS[0]]))

        assert repo_map == {"acme/widgets": [4711]}
        assert api.paths == ["/orgs/acme/teams/payments/repos"]

    @pytest.mark.asyncio
    async def test_a_listing_that_does_not_say_what_the_access_is_stops_at_that_page(self, fake_cache):
        service = _service()
        pages = {1: _page([{"full_name": "acme/widgets"}], has_next=True), 2: _page([_held_repository("acme/api")])}

        async def _answer(_path, params):
            return pages[params["page"]]

        api = _GitHubApi(_answer)
        with patch.object(service, "_api_client", new=api.client):
            assert await service.get_org_repository_map("acme", {4711: "payments"}) is None

        assert [params["page"] for _path, params in api.requests] == [1]

    @pytest.mark.asyncio
    async def test_another_instance_walks_while_one_saturates_its_gate(self, fake_cache):
        """GitHub limits concurrency per token, so another token queueing here protects nothing."""
        busy, other = _service("gh-busy"), _service("gh-other")
        released = asyncio.Event()
        busy_api = self._listings({slug: [] for slug in self._teams(16).values()}, released=released)
        other_api = self._listings({"payments": ["acme/widgets"]})

        with (
            patch.object(busy, "_api_client", new=busy_api.client),
            patch.object(other, "_api_client", new=other_api.client),
        ):
            busy_walk = asyncio.create_task(busy.get_org_repository_map("big", self._teams(16)))
            await asyncio.sleep(0.01)
            try:
                repo_map = await asyncio.wait_for(other.get_org_repository_map("acme", {4711: "payments"}), 1.0)
            finally:
                released.set()
                await busy_walk

        assert repo_map == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    async def test_the_walk_budget_starts_once_the_walk_gets_the_gate(self, fake_cache):
        """A walk paying for the queue behind another organisation's walk timed out and held its
        organisation undetermined for the hour the failure is cached."""
        service = _service()
        held = {**{slug: [] for slug in self._teams(16).values()}, "payments": ["acme/widgets"]}
        api = self._listings(held, delay=0.2)

        with (
            patch("app.services.github._GITHUB_ORG_WALK_TIMEOUT", 0.3),
            patch.object(service, "_api_client", new=api.client),
        ):
            big = asyncio.create_task(service.get_org_repository_map("big", self._teams(16)))
            await asyncio.sleep(0.01)
            small = await service.get_org_repository_map("acme", {4711: "payments"})
            await big

        assert small == {"acme/widgets": [4711]}

    @pytest.mark.asyncio
    async def test_a_waiter_never_walks_beside_a_walker_still_queued_at_the_gate(self, fake_cache):
        """The walk budget starts at the gate, so the queue before it counts against no budget of the
        walk's; a waiter that gave up then and walked as well is the stampede the lock is for."""
        service = _service()
        api = self._listings({"payments": ["acme/widgets"]})
        gate = _org_walk_gate(str(service.instance.id))
        for _ in range(_GITHUB_ORG_WALK_CONCURRENCY):
            await gate.acquire()

        with (
            patch("app.services.github._GITHUB_ORG_WALK_TIMEOUT", 0.1),
            patch("app.services.github._GITHUB_RESOLUTION_TIMEOUT", 2.0),
            patch.object(service, "_api_client", new=api.client),
        ):
            walker = asyncio.create_task(service.get_org_repository_map("acme", {4711: "payments"}))
            await asyncio.sleep(0.01)
            waiter = asyncio.create_task(service.get_org_repository_map("acme", {4711: "payments"}))
            await asyncio.sleep(0.5)
            for _ in range(_GITHUB_ORG_WALK_CONCURRENCY):
                gate.release()
            results = await asyncio.gather(walker, waiter)

        assert results == [{"acme/widgets": [4711]}] * 2
        assert api.paths == ["/orgs/acme/teams/payments/repos"]


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
            {"login": "ada", "role": "admin"},
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

        assert renamed == [{"login": "ada", "role": "admin"}, {"login": "ada", "role": "member"}]
        assert paginated.await_count == 2

    @pytest.mark.asyncio
    async def test_two_ingests_arriving_together_list_the_members_once(self, fake_cache):
        service = _service()

        async def _answer(_path, _params):
            await asyncio.sleep(0.02)
            return _page([{"login": "ada", "id": 1, "type": "User"}])

        api = _GitHubApi(_answer)
        with patch.object(service, "_api_client", new=api.client):
            await asyncio.gather(*(service.get_team_members("acme", "payments", 4711) for _ in range(2)))

        assert [params["role"] for _path, params in api.requests] == ["maintainer", "member"]

    @pytest.mark.asyncio
    async def test_the_listings_share_the_instance_gate(self, fake_cache):
        service = _service()

        async def _answer(_path, _params):
            await asyncio.sleep(0.01)
            return _page([])

        api = _GitHubApi(_answer)
        with patch.object(service, "_api_client", new=api.client):
            await asyncio.gather(*(service.get_team_members("acme", f"t{index}", index) for index in range(40)))

        assert api.peak == _GITHUB_ORG_WALK_CONCURRENCY


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
            assert await service._public_emails(["ada"]) == {"ada": "ada@example.com"}

        assert api_get.await_args.args[0] == "/users/ada"

    @pytest.mark.asyncio
    async def test_returns_none_when_the_profile_hides_it(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_profile(None))):
            assert await service._public_emails(["ada"]) == {"ada": ""}

    @pytest.mark.asyncio
    async def test_a_refusal_is_logged_rather_than_read_as_a_hidden_email(self, fake_cache, caplog):
        service = _service()
        response = MagicMock(status_code=403)
        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)):
            with caplog.at_level("WARNING", logger="app.services.github"):
                # Undetermined, not "this profile hides its email": the caller retires a member on
                # the second answer and must not on the first.
                assert await service._public_emails(["ada"]) is None

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
                assert await service._public_emails(["ghost"]) == {"ghost": ""}

        assert [r.getMessage() for r in caplog.records if r.levelname == "WARNING"] == []


class TestPublicProfileEmailCaching:
    """The per-member lookup outnumbers the three list calls; uncached it walks straight past them."""

    @pytest.mark.asyncio
    async def test_the_second_lookup_of_a_login_is_served_from_the_cache(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_profile("ada@example.com"))) as api_get:
            assert await service._public_emails(["ada"]) == {"ada": "ada@example.com"}
            assert await service._public_emails(["ada"]) == {"ada": "ada@example.com"}

        assert api_get.await_count == 1

    @pytest.mark.asyncio
    async def test_a_hidden_email_is_cached_too(self, fake_cache):
        """Bots and private profiles are the routine answer, so refetching them is what burns the budget."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_profile(None))) as api_get:
            assert await service._public_emails(["dependabot"]) == {"dependabot": ""}
            assert await service._public_emails(["dependabot"]) == {"dependabot": ""}

        assert api_get.await_count == 1

    @pytest.mark.asyncio
    async def test_an_unknown_login_is_cached_too(self, fake_cache):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=MagicMock(status_code=404))) as api_get:
            assert await service._public_emails(["ghost"]) == {"ghost": ""}
            assert await service._public_emails(["ghost"]) == {"ghost": ""}

        assert api_get.await_count == 1

    @pytest.mark.asyncio
    async def test_one_login_never_answers_for_another(self, fake_cache):
        service = _service()

        async def _by_login(endpoint, params=None):
            return _profile(f"{endpoint.rsplit('/', 1)[1]}@example.com")

        with patch.object(service, "_api_get", new=AsyncMock(side_effect=_by_login)):
            assert await service._public_emails(["ada"]) == {"ada": "ada@example.com"}
            assert await service._public_emails(["bob"]) == {"bob": "bob@example.com"}

    @pytest.mark.asyncio
    async def test_a_refusal_is_not_cached(self, fake_cache):
        """A throttled 403 held for the TTL would strip email matching from every later job of the run."""
        service = _service()
        responses = [MagicMock(status_code=403), _profile("ada@example.com")]
        with patch.object(service, "_api_get", new=AsyncMock(side_effect=responses)):
            assert await service._public_emails(["ada"]) is None
            assert await service._public_emails(["ada"]) == {"ada": "ada@example.com"}

    @pytest.mark.asyncio
    async def test_a_second_instance_does_not_read_the_first_ones_entry(self, fake_cache):
        """Two instances are two tokens against two user namespaces; GHES logins are not github.com logins."""
        first = GitHubService(make_github_instance(id="gh-1", access_token="ghp-secret"))
        second = GitHubService(make_github_instance(id="gh-2", access_token="ghp-other"))

        with patch.object(first, "_api_get", new=AsyncMock(return_value=_profile("ada@example.com"))):
            assert await first._public_emails(["ada"]) == {"ada": "ada@example.com"}
        with patch.object(second, "_api_get", new=AsyncMock(return_value=_profile("ada@ghes.internal"))):
            assert await second._public_emails(["ada"]) == {"ada": "ada@ghes.internal"}


class TestMemberResolution:
    """Every holder's members are resolved on every ingest, so what one resolution costs is what
    every job of every workflow run pays."""

    _HOLDER = _HolderBinding(4711, "payments", {"_id": "t-pay", "name": "Payments", "bindings": []})

    @staticmethod
    def _api(profiles: dict[str, tuple[int, dict]]) -> _GitHubApi:
        """The team's members (all on role=member) and GET /users/{login} for each of them."""

        async def _answer(path, params):
            await asyncio.sleep(0)
            if path == "/orgs/acme/teams/payments/members":
                logins = list(profiles) if params["role"] == "member" else []
                return _page([{"login": login, "id": index, "type": "User"} for index, login in enumerate(logins)])
            status, body = profiles[path.removeprefix("/users/")]
            return _response(status, body)

        return _GitHubApi(_answer)

    @staticmethod
    async def _users() -> UserRepository:
        repo = UserRepository(FakeDatabase())
        for login in ("ada", "bob"):
            await repo.create_raw(
                {"_id": f"u-{login}", "username": f"d{login}", "email": f"{login}@acme.io", "is_verified": True}
            )
        return repo

    @pytest.mark.asyncio
    async def test_only_the_profiles_not_cached_are_read_and_the_users_are_found_in_one_query(self, fake_cache):
        service = _service()
        await fake_cache.set(service._get_cache_key("user_email:ada"), "ada@acme.io")
        api = self._api(
            {
                "ada": (200, {"login": "ada", "email": "ada@acme.io"}),
                "bob": (200, {"login": "bob", "email": "Bob@Acme.io"}),
                "cyd": (404, {"message": "Not Found"}),
            }
        )
        users = await self._users()

        with (
            patch.object(service, "_api_client", new=api.client),
            patch.object(users.collection, "find", wraps=users.collection.find) as find,
            patch.object(users.collection, "find_one", wraps=users.collection.find_one) as find_one,
        ):
            members = await service._resolve_holder_members(users, "acme", "widgets", self._HOLDER)

        assert {member.user_id for member in members} == {"u-ada", "u-bob"}
        assert sorted(path for path in api.paths if path.startswith("/users/")) == ["/users/bob", "/users/cyd"]
        assert (find.call_count, find_one.call_count) == (1, 0)

    @pytest.mark.asyncio
    async def test_a_maintainer_becomes_a_team_admin_and_a_member_a_member(self, fake_cache):
        service = _service()

        async def _answer(path, params):
            if path == "/orgs/acme/teams/payments/members":
                login = "ada" if params["role"] == "maintainer" else "bob"
                return _page([{"login": login, "id": 1, "type": "User"}])
            login = path.removeprefix("/users/")
            return _response(200, {"login": login, "email": f"{login}@acme.io"})

        with patch.object(service, "_api_client", new=_GitHubApi(_answer).client):
            listed = await service.get_team_members("acme", "payments", 4711)
            resolved = await service._build_team_members(listed, await self._users())

        assert {(member.user_id, member.role) for member in resolved} == {
            ("u-ada", "admin"),
            ("u-bob", "member"),
        }

    @pytest.mark.asyncio
    async def test_a_refusal_stops_the_profile_reads_still_to_come(self, fake_cache):
        """A throttled token otherwise spends a failing request per member of every holder, on
        every ingest, for a result that is thrown away."""
        service = _service()
        refused = (403, {"message": "API rate limit exceeded for installation ID 1234."})
        api = self._api({f"user{index}": refused for index in range(40)})

        with patch.object(service, "_api_client", new=api.client):
            members = await service._resolve_holder_members(await self._users(), "acme", "widgets", self._HOLDER)

        assert members is None
        assert len([path for path in api.paths if path.startswith("/users/")]) <= _GITHUB_ORG_WALK_CONCURRENCY

    @pytest.mark.asyncio
    async def test_a_profile_email_is_kept_for_hours(self, fake_cache):
        """Profile emails rarely change, and re-reading every member's every five minutes was the
        token's whole hourly budget for ten busy teams."""
        service = _service()
        api = self._api({"bob": (200, {"login": "bob", "email": "bob@acme.io"})})

        with patch.object(service, "_api_client", new=api.client):
            await service._resolve_holder_members(await self._users(), "acme", "widgets", self._HOLDER)

        assert await fake_cache._client.ttl(fake_cache._make_key(service._get_cache_key("user_email:bob"))) > 3600


# 2026-09-09 15:04:00 UTC, the shape GitHub sends: seconds since the epoch.
_RESET_EPOCH = 1788966240
_RESET_AT = datetime(2026, 9, 9, 15, 4, tzinfo=timezone.utc)


def _rate_limit_response(core_remaining: int, rate_remaining: int = 4321) -> MagicMock:
    response = MagicMock(status_code=200)
    response.json = MagicMock(
        return_value={
            "resources": {
                "core": {
                    "limit": 5000,
                    "used": 5000 - core_remaining,
                    "remaining": core_remaining,
                    "reset": _RESET_EPOCH,
                },
                "graphql": {"limit": 5000, "used": 0, "remaining": 5000, "reset": _RESET_EPOCH + 60},
                "search": {"limit": 30, "used": 0, "remaining": 30, "reset": _RESET_EPOCH + 120},
            },
            "rate": {
                "limit": 5000,
                "used": 5000 - rate_remaining,
                "remaining": rate_remaining,
                "reset": _RESET_EPOCH + 180,
            },
        }
    )
    return response


class TestCoreRateLimit:
    """Told apart from a scope refusal only by an endpoint GitHub answers while everything else 403s."""

    @pytest.mark.asyncio
    async def test_is_read_from_the_endpoint_that_costs_no_budget(self):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_rate_limit_response(0))) as api_get:
            limit = await service.get_core_rate_limit()

        assert api_get.await_args.args[0] == "/rate_limit"
        assert limit is not None
        assert limit.remaining == 0
        assert limit.reset_at == _RESET_AT

    @pytest.mark.asyncio
    async def test_reports_the_core_resource_rather_than_the_deprecated_rate_block(self):
        """``rate`` is a legacy alias GitHub keeps for search-era clients; team sync spends ``core``."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_rate_limit_response(0, rate_remaining=99))):
            limit = await service.get_core_rate_limit()

        assert limit is not None
        assert limit.remaining == 0
        assert limit.reset_at == _RESET_AT

    @pytest.mark.asyncio
    async def test_a_budget_still_standing_is_reported_as_such(self):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=_rate_limit_response(4999))):
            limit = await service.get_core_rate_limit()

        assert limit is not None
        assert limit.remaining == 4999

    @pytest.mark.asyncio
    async def test_a_refused_endpoint_is_none_rather_than_a_zero_budget(self):
        """GHES with rate limiting switched off answers 404; that is not a throttled token."""
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=MagicMock(status_code=404))):
            assert await service.get_core_rate_limit() is None

    @pytest.mark.asyncio
    async def test_an_unreachable_endpoint_is_none(self):
        service = _service()
        with patch.object(service, "_api_get", new=AsyncMock(return_value=None)):
            assert await service.get_core_rate_limit() is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"resources": {}},
            {"resources": {"core": {"remaining": 0}}},
            {"resources": {"core": {"remaining": "none", "reset": _RESET_EPOCH}}},
            {"resources": {"core": {"remaining": 0, "reset": "soon"}}},
        ],
    )
    async def test_a_body_it_cannot_read_is_none_rather_than_a_crash(self, body):
        """A parse error here must degrade to the scope message, not 500 the connection test."""
        service = _service()
        response = MagicMock(status_code=200)
        response.json = MagicMock(return_value=body)
        with patch.object(service, "_api_get", new=AsyncMock(return_value=response)):
            assert await service.get_core_rate_limit() is None
