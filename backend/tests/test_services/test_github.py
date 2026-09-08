"""Tests for GitHubService OIDC validation and API pagination."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.github_api import GitHubOIDCPayload
from app.services.github import GitHubService
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

    def test_api_url_empty_github_url_defaults_to_public(self):
        instance = make_github_instance(github_url="")
        service = GitHubService(instance)
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
            mock_jwks.return_value = {"keys": [{"kid": "test-key-id", "kty": "RSA", "n": "n", "e": "AQAB"}]}
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
            mock_jwks.return_value = {"keys": [{"kid": "test-key-id", "kty": "RSA", "n": "n", "e": "AQAB"}]}
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
            mock_jwks.return_value = {"keys": [{"kid": "other-key", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch.object(service, "_invalidate_jwks_cache", new_callable=AsyncMock):
                with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "missing-key"}
                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None

    def test_returns_payload_on_success(self):
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
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
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
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
        """When key is not in cached JWKS, should invalidate and retry."""
        instance = github_instance_a()
        service = GitHubService(instance)

        jwks_old = {"keys": [{"kid": "old-key", "kty": "RSA", "n": "n", "e": "AQAB"}]}
        jwks_new = {
            "keys": [
                {"kid": "old-key", "kty": "RSA", "n": "n", "e": "AQAB"},
                {"kid": "new-key", "kty": "RSA", "n": "n2", "e": "AQAB"},
            ]
        }

        call_count = 0

        def get_jwks_side_effect():
            nonlocal call_count
            call_count += 1
            return jwks_old if call_count == 1 else jwks_new

        with patch.object(service, "get_jwks", new_callable=AsyncMock, side_effect=get_jwks_side_effect):
            with patch.object(service, "_invalidate_jwks_cache", new_callable=AsyncMock) as mock_invalidate:
                with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "new-key"}
                    with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                        mock_decode.return_value = {
                            "repository_id": "42",
                            "repository": "o/p",
                            "repository_owner": "o",
                            "actor": "u",
                        }

                        result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))

                        assert isinstance(result, GitHubOIDCPayload)
                        assert result.repository_id == "42"
                        mock_invalidate.assert_called_once()
                        assert call_count == 2

    def test_uses_rs256_algorithm(self):
        """GitHub OIDC tokens use RS256, verify the service enforces this."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
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
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
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
        """If jwt.decode raises, should return None (not crash)."""
        instance = github_instance_a()
        service = GitHubService(instance)

        with patch.object(service, "get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA", "n": "n", "e": "AQAB"}]}
            with patch("app.services.oidc_utils.jwt.get_unverified_header") as mock_header:
                mock_header.return_value = {"kid": "k1"}
                with patch("app.services.oidc_utils.jwt.decode") as mock_decode:
                    mock_decode.side_effect = Exception("Signature verification failed")

                    result = asyncio.run(service.validate_oidc_token("fake.jwt.token"))
                    assert result is None


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

    class _CM:
        async def __aenter__(self):
            return mock_client

        async def __aexit__(self, *a):
            return False

    return patch.object(service, "_api_client", return_value=_CM())


class TestGitHubPaginationCap:
    def test_cap_truncates_and_warns_naming_the_endpoint(self, caplog):
        """A hit cap must be visible: the result stops at the cap AND a WARNING names endpoint, cap and item count."""
        service = GitHubService(make_github_instance(access_token="ghp-test-token"))
        fetched_pages: list[int] = []

        with _patch_three_pages(service, fetched_pages):
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = asyncio.run(service._api_get_paginated(_TEAMS_ENDPOINT, max_pages=2))

        assert fetched_pages == [1, 2]
        assert result is not None
        assert [t["slug"] for t in result] == ["payments", "platform"]

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
        message = warnings[0].getMessage()
        assert _TEAMS_ENDPOINT in message
        assert "cap of 2 page(s)" in message
        assert "(2 items)" in message
        assert "TRUNCATED" in message

    def test_max_pages_none_fetches_every_page(self, caplog):
        """max_pages=None is uncapped: all three pages are fetched and nothing warns."""
        service = GitHubService(make_github_instance(access_token="ghp-test-token"))
        fetched_pages: list[int] = []

        with _patch_three_pages(service, fetched_pages):
            with caplog.at_level("WARNING", logger="app.services.github"):
                result = asyncio.run(service._api_get_paginated(_TEAMS_ENDPOINT, max_pages=None))

        assert fetched_pages == [1, 2, 3]
        assert result is not None
        assert [t["slug"] for t in result] == ["payments", "platform", "sre"]
        assert [r for r in caplog.records if r.levelname == "WARNING"] == []
