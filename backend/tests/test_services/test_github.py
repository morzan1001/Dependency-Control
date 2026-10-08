"""Tests for GitHubService OIDC validation, API pagination and write verbs."""

import asyncio
from functools import partial
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt
import pytest

from app.models.github_api import GitHubOIDCPayload
from app.services.github import GitHubService
from tests.helpers.oidc import rsa_public_jwk
from tests.mocks.github import github_instance_a, github_instance_b, make_github_instance


class TestGitHubServiceInitialization:
    def test_with_instance(self):
        instance = github_instance_a()
        service = GitHubService(instance)
        assert service.instance == instance
        assert service.base_url == "https://token.actions.githubusercontent.com"

    def test_strips_trailing_slash(self):
        instance = make_github_instance(url="https://token.actions.githubusercontent.com/")
        service = GitHubService(instance)
        assert service.base_url == "https://token.actions.githubusercontent.com"

    def test_strips_multiple_trailing_slashes(self):
        instance = make_github_instance(url="https://github.corp.example.com//")
        service = GitHubService(instance)
        assert service.base_url == "https://github.corp.example.com"

    def test_api_url_for_github_com(self):
        instance = make_github_instance(github_url="https://github.com")
        service = GitHubService(instance)
        assert service.api_url == "https://api.github.com"

    def test_api_url_for_www_github_com(self):
        instance = make_github_instance(github_url="https://www.github.com")
        service = GitHubService(instance)
        assert service.api_url == "https://api.github.com"

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://token.actions.githubusercontent.com",
            "https://token.actions.githubusercontent.com/acme-enterprise",
        ],
    )
    def test_api_url_without_a_web_url_is_public_for_the_actions_issuer(self, issuer):
        service = GitHubService(make_github_instance(url=issuer, github_url=None))
        assert service.api_url == "https://api.github.com"

    def test_api_url_for_ghes(self):
        instance = make_github_instance(github_url="https://github.corp.example.com")
        service = GitHubService(instance)
        assert service.api_url == "https://github.corp.example.com/api/v3"

    def test_ghes_host_with_github_com_prefix_not_misrouted(self):
        """A GHES host whose name merely contains 'github.com' as a substring must resolve to its own /api/v3, never the public api.github.com (which would leak the enterprise PAT)."""
        for ghes_url in (
            "https://github.company.com",
            "https://github.commerce.io",
            "https://github.com.mycorp.internal",
        ):
            instance = make_github_instance(github_url=ghes_url)
            service = GitHubService(instance)
            assert service.api_url == f"{ghes_url}/api/v3", ghes_url
            assert service.api_url != "https://api.github.com", ghes_url


class TestGitHubServiceCacheKeys:
    def test_uses_instance_id(self):
        instance = github_instance_a()
        service = GitHubService(instance)
        key = service._get_cache_key("jwks")
        assert "gh-instance-a-id" in key
        assert key.startswith("github:")

    def test_differ_between_instances(self):
        service_a = GitHubService(github_instance_a())
        service_b = GitHubService(github_instance_b())
        key_a = service_a._get_cache_key("jwks")
        key_b = service_b._get_cache_key("jwks")
        assert key_a != key_b
        assert "gh-instance-a-id" in key_a
        assert "gh-instance-b-id" in key_b


class TestGitHubServiceOIDC:
    def test_uses_instance_issuer(self):
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("test-key-id")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123",
                        "repository": "owner/repo",
                        "repository_owner": "owner",
                        "actor": "user",
                    }

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["issuer"] == "https://token.actions.githubusercontent.com"
                    assert call_kwargs["audience"] == "dependency-control"

    def test_rejected_when_no_audience_configured(self):
        """An instance without a configured oidc_audience must reject any token (fail closed), never decode it."""
        instance = make_github_instance(oidc_audience=None)
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("test-key-id")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "test-key-id"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123",
                        "repository": "owner/repo",
                        "repository_owner": "owner",
                        "actor": "user",
                    }

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    # Token rejected, and decode is never attempted.
                    assert result is None
                    mock_decode.assert_not_called()

    def test_missing_kid_returns_none(self):
        instance = github_instance_a()
        service = GitHubService(instance)
        with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
            mock_header.return_value = {}  # No kid
            result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
            assert result is None

    def test_no_matching_key_returns_none(self):
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("other-key")]}
            with patch.object(service, "refresh_jwks", new_callable=AsyncMock, return_value=None):
                with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "missing-key"}
                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None

    def test_returns_payload_on_success(self):
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("k1")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123456",
                        "repository": "owner/my-repo",
                        "repository_owner": "owner",
                        "actor": "developer",
                    }

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert isinstance(result, GitHubOIDCPayload)
                    assert result.repository_id == "123456"
                    assert result.repository == "owner/my-repo"
                    assert result.actor == "developer"

    def test_issuer_uses_normalized_url(self):
        """Issuer verification must use URL without trailing slash."""
        instance = make_github_instance(url="https://token.actions.githubusercontent.com/")
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("k1")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "123",
                        "repository": "o/r",
                        "repository_owner": "o",
                        "actor": "u",
                    }

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["issuer"] == "https://token.actions.githubusercontent.com"

    def test_key_rotation_refreshes_jwks(self):
        """A kid missing from the cached set is looked up in a refetched one."""
        service = GitHubService(github_instance_a())
        jwks_old = {"keys": [rsa_public_jwk("old-key")]}
        jwks_new = {"keys": [*jwks_old["keys"], rsa_public_jwk("new-key")]}
        claims = {"repository_id": "42", "repository": "o/p", "repository_owner": "o", "actor": "u"}

        with (
            patch.object(service, "get_jwks", new_callable=AsyncMock, return_value=jwks_old),
            patch.object(service, "refresh_jwks", new_callable=AsyncMock, return_value=jwks_new) as refresh,
            patch("app.services.oidc_utils.jwt.get_unverified_header", return_value={"kid": "new-key"}),
            patch("app.services.oidc_utils.jwt.decode", return_value=claims),
        ):
            result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

        assert isinstance(result, GitHubOIDCPayload)
        assert result.repository_id == "42"
        refresh.assert_awaited_once()

    def test_uses_rs256_algorithm(self):
        """GitHub OIDC tokens use RS256, verify the service enforces this."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("k1")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "1",
                        "repository": "o/r",
                        "repository_owner": "o",
                        "actor": "u",
                    }

                    asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                    call_kwargs = mock_decode.call_args.kwargs
                    assert call_kwargs["algorithms"] == ["RS256"]

    def test_extra_claims_ignored(self):
        """GitHubOIDCPayload uses extra='ignore', non-standard claims should not cause errors."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("k1")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.return_value = {
                        "repository_id": "1",
                        "repository": "o/r",
                        "repository_owner": "o",
                        "actor": "u",
                        "iss": "https://token.actions.githubusercontent.com",
                        "sub": "repo:o/r:ref:refs/heads/main",
                        "aud": "dependency-control",
                        "custom_claim": "should-be-ignored",
                    }

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert isinstance(result, GitHubOIDCPayload)
                    assert result.repository_id == "1"

    def test_decode_exception_returns_none(self):
        """A token the decoder rejects is a failed validation, not a crash."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [rsa_public_jwk("k1")]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.side_effect = jwt.InvalidSignatureError("Signature verification failed")

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None


_JWKS = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}


@pytest.fixture
def jwks_cache(fake_cache, monkeypatch):
    monkeypatch.setattr("app.services.oidc_utils.cache_service", fake_cache)
    monkeypatch.setattr("app.services.github.cache_service", fake_cache)
    return fake_cache


def _serve_idp(monkeypatch, handler):
    requested: list[str] = []

    async def recording(request):
        requested.append(str(request.url))
        return handler(request)

    monkeypatch.setattr(httpx, "AsyncClient", partial(httpx.AsyncClient, transport=httpx.MockTransport(recording)))
    return requested


@pytest.mark.asyncio
class TestGitHubJwksSource:
    async def test_github_com_keys_come_from_the_fixed_location(self, monkeypatch, jwks_cache):
        requested = _serve_idp(monkeypatch, lambda request: httpx.Response(200, json=_JWKS))

        assert await GitHubService(github_instance_a()).get_jwks() == _JWKS
        assert requested == ["https://token.actions.githubusercontent.com/.well-known/jwks"]

    async def test_ghes_without_discovery_falls_back_without_remembering_the_guess(self, monkeypatch, jwks_cache):
        base = "https://github.corp.example.com/_services/token"
        rotated = {"keys": [{"kid": "k2", "kty": "RSA", "n": "n2", "e": "AQAB"}]}
        discovery = {"up": False}

        def handler(request):
            if request.url.path.endswith("/openid-configuration"):
                if discovery["up"]:
                    return httpx.Response(200, json={"jwks_uri": f"{base}/keys"})
                return httpx.Response(404)
            return httpx.Response(200, json=rotated if request.url.path.endswith("/keys") else _JWKS)

        requested = _serve_idp(monkeypatch, handler)
        service = GitHubService(github_instance_b())
        assert await service.get_jwks() == _JWKS
        assert requested == [f"{base}/.well-known/openid-configuration", f"{base}/.well-known/jwks"]

        discovery["up"] = True
        assert await service.refresh_jwks() == rotated

    async def test_a_malformed_issuer_serves_no_key_set(self, monkeypatch, jwks_cache):
        requested = _serve_idp(monkeypatch, lambda request: httpx.Response(200, json=_JWKS))
        service = GitHubService(make_github_instance(url="https://github.corp.example.com:_services/token"))

        assert await service.get_jwks() is None
        assert requested == []


_TEAMS_ENDPOINT = "/repos/acme/widgets/teams"
_TEAMS_URL = f"https://api.github.com{_TEAMS_ENDPOINT}"

# Shape of GET /repos/{owner}/{repo}/teams, one team per page.
_TEAM_PAGES = [
    [
        {
            "id": 501,
            "node_id": "T_kwDOA",
            "name": "Payments",
            "slug": "payments",
            "description": None,
            "privacy": "closed",
            "permission": "push",
            "url": "https://api.github.com/organizations/9/team/501",
            "html_url": "https://github.com/orgs/acme/teams/payments",
            "members_url": "https://api.github.com/organizations/9/team/501/members{/member}",
            "repositories_url": "https://api.github.com/organizations/9/team/501/repos",
            "parent": None,
        }
    ],
    [
        {
            "id": 502,
            "node_id": "T_kwDOB",
            "name": "Platform",
            "slug": "platform",
            "description": None,
            "privacy": "closed",
            "permission": "pull",
            "url": "https://api.github.com/organizations/9/team/502",
            "html_url": "https://github.com/orgs/acme/teams/platform",
            "members_url": "https://api.github.com/organizations/9/team/502/members{/member}",
            "repositories_url": "https://api.github.com/organizations/9/team/502/repos",
            "parent": None,
        }
    ],
    [
        {
            "id": 503,
            "node_id": "T_kwDOC",
            "name": "SRE",
            "slug": "sre",
            "description": None,
            "privacy": "closed",
            "permission": "admin",
            "url": "https://api.github.com/organizations/9/team/503",
            "html_url": "https://github.com/orgs/acme/teams/sre",
            "members_url": "https://api.github.com/organizations/9/team/503/members{/member}",
            "repositories_url": "https://api.github.com/organizations/9/team/503/repos",
            "parent": None,
        }
    ],
]


def _link_header(page: int) -> str:
    """GitHub's Link header: rel="next" on every page but the last."""
    if page >= len(_TEAM_PAGES):
        return f'<{_TEAMS_URL}?per_page=100&page=1>; rel="first", <{_TEAMS_URL}?per_page=100&page=2>; rel="prev"'
    return (
        f'<{_TEAMS_URL}?per_page=100&page={page + 1}>; rel="next", '
        f'<{_TEAMS_URL}?per_page=100&page={len(_TEAM_PAGES)}>; rel="last"'
    )


def _patch_api_client(service, mock_client):
    class _CM:
        async def __aenter__(self):
            return mock_client

        async def __aexit__(self, *a):
            return False

    return patch.object(service, "_api_client", return_value=_CM())


def _patch_three_pages(service, fetched_pages):
    async def fake_get(url, headers=None, params=None):
        page = params["page"]
        fetched_pages.append(page)
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = _TEAM_PAGES[page - 1]
        response.headers = {"link": _link_header(page)}
        return response

    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=fake_get)

    return _patch_api_client(service, mock_client)


class TestGitHubPagination:
    def test_follows_the_link_header_to_the_last_page(self, caplog):
        service = GitHubService(make_github_instance(access_token="ghp-test-token"))
        fetched_pages: list[int] = []

        with _patch_three_pages(service, fetched_pages):
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = asyncio.run(service._api_get_paginated(_TEAMS_ENDPOINT))

        assert fetched_pages == [1, 2, 3]
        assert result is not None
        assert [t["slug"] for t in result] == ["payments", "platform", "sre"]
        assert [r for r in caplog.records if r.levelname == "WARNING"] == []


_COMMENT_WRITES = [
    pytest.param("POST", "/repos/o/r/issues/1/comments", id="post"),
    pytest.param("PATCH", "/repos/o/r/issues/comments/9", id="patch"),
]


class TestGitHubApiWriteMethods:
    """A write must fail closed without a token and must hit the right verb and URL."""

    @pytest.mark.parametrize(("method", "endpoint"), _COMMENT_WRITES)
    def test_a_write_without_a_token_opens_no_client(self, method, endpoint):
        """The guard must short-circuit before any client opens, not lean on _get_auth_headers raising."""
        service = GitHubService(make_github_instance(access_token=None))

        with _patch_api_client(service, MagicMock()) as api_client:
            assert asyncio.run(service._api_request(method, endpoint, json_data={"body": "x"})) is None

        api_client.assert_not_called()

    @pytest.mark.parametrize(("method", "endpoint"), _COMMENT_WRITES)
    def test_a_write_sends_its_verb_and_json_body_to_the_api_url(self, method, endpoint):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        mock_client = MagicMock()
        mock_client.request = AsyncMock(return_value=MagicMock(status_code=201))

        with _patch_api_client(service, mock_client):
            response = asyncio.run(service._api_request(method, endpoint, json_data={"body": "hello"}))

        assert response is not None
        assert response.status_code == 201
        assert mock_client.request.call_args.args == (method, f"https://api.github.com{endpoint}")
        kwargs = mock_client.request.call_args.kwargs
        assert kwargs["json"] == {"body": "hello"}
        assert kwargs["headers"]["Authorization"] == "Bearer ghp-x"

    def test_api_write_uses_the_ghes_api_url(self):
        service = GitHubService(
            make_github_instance(access_token="ghp-x", github_url="https://github.corp.example.com")
        )
        mock_client = MagicMock()
        mock_client.request = AsyncMock(return_value=MagicMock(status_code=201))

        with _patch_api_client(service, mock_client):
            asyncio.run(service._api_request("POST", "/repos/o/r/issues/1/comments", json_data={"body": "x"}))

        assert mock_client.request.call_args.args[1] == (
            "https://github.corp.example.com/api/v3/repos/o/r/issues/1/comments"
        )

    @pytest.mark.parametrize(("method", "endpoint"), _COMMENT_WRITES)
    def test_a_write_returns_none_on_transport_error(self, method, endpoint):
        service = GitHubService(make_github_instance(access_token="ghp-x"))
        mock_client = MagicMock()
        mock_client.request = AsyncMock(side_effect=RuntimeError("connection reset"))

        with _patch_api_client(service, mock_client):
            assert asyncio.run(service._api_request(method, endpoint, json_data={"body": "x"})) is None


class TestGhesInstanceWithoutWebUrl:
    """A GHES issuer with no web URL has no known API host, so its token must go nowhere, least of all github.com."""

    @staticmethod
    def _service() -> GitHubService:
        return GitHubService(
            make_github_instance(
                url="https://ghes.corp.example/_services/token", github_url=None, access_token="ghes-pat"
            )
        )

    @pytest.mark.parametrize(
        "call",
        [
            pytest.param(lambda s: s._api_get("/user"), id="get"),
            pytest.param(lambda s: s._api_request("POST", "/repos/o/r/issues/1/comments"), id="post"),
            pytest.param(lambda s: s._api_request("PATCH", "/repos/o/r/issues/comments/9"), id="patch"),
            pytest.param(lambda s: s._api_get_paginated("/orgs/acme/teams"), id="paginated"),
        ],
    )
    def test_no_request_is_sent(self, call):
        service = self._service()

        with _patch_api_client(service, MagicMock()) as api_client:
            assert asyncio.run(call(service)) is None

        api_client.assert_not_called()
